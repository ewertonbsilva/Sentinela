"""Funcoes puras do painel CrowdSec: transformam alertas da LAPI, metricas do Prometheus e arquivos de
configuracao em dados prontos para a tela. Nada aqui faz rede nem escreve em disco (so le arquivos de
configuracao do CrowdSec, em modo leitura), por isso tudo e testavel com os dados reais de tests_data/.

Todo texto que vem de quem atacou (caminho, user-agent, hostname...) passa aqui como dado; quem o exibe
(app.js) usa textContent, nunca innerHTML.
"""
import csv
import io
import ipaddress
import json
import os
import re
import time
from collections import Counter
from datetime import datetime, timedelta, timezone

def _fuso():
    """Fuso de exibicao (PAINEL_TZ, nome IANA). Sem o banco de fusos do sistema, cai em UTC-3 e avisa no log."""
    nome = os.environ.get("PAINEL_TZ", "America/Sao_Paulo")
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(nome), nome
    except Exception:
        print("aviso: fuso %r indisponivel (instale tzdata); usando UTC-3" % nome, flush=True)
        return timezone(timedelta(hours=-3)), nome


TZ, TZ_NOME = _fuso()
META_PADRAO = ("http_verb", "http_path", "http_status", "target_fqdn", "user_agent")
META_RUIDO = {"source_ip", "log_type", "service", "datasource_path", "datasource_type", "timestamp"}


# ---------------------------------------------------------------- tempo e formatos
def parse_iso(s):
    if not s:
        return None
    s = s.strip().replace("Z", "+00:00")
    m = re.search(r"\.(\d+)", s)
    if m:
        s = s.replace(m.group(0), "." + m.group(1)[:6].ljust(6, "0"))
    try:
        d = datetime.fromisoformat(s)
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def duracao_s(s):
    """'3h59m55.123s' -> segundos; None se vazio, invalido ou ja expirado (negativo)."""
    if not s or str(s).startswith("-"):
        return None
    m = re.fullmatch(r"(?:(\d+)h)?(?:(\d+)m)?(?:([\d.]+)s)?", str(s))
    if not m or not any(m.groups()):
        return None
    return int(m.group(1) or 0) * 3600 + int(m.group(2) or 0) * 60 + int(float(m.group(3) or 0))


def fmt_duracao(s):
    """'3h59m55.123s' -> '3h 59m'; vazio ou negativo -> None (ja expirou)."""
    if not s or str(s).startswith("-"):
        return None
    m = re.fullmatch(r"(?:(\d+)h)?(?:(\d+)m)?(?:([\d.]+)s)?", str(s))
    if not m:
        return str(s)
    h, mi, se = int(m.group(1) or 0), int(m.group(2) or 0), float(m.group(3) or 0)
    if h >= 24:
        return "%dd %dh" % (h // 24, h % 24)
    if h:
        return "%dh %02dm" % (h, mi)
    if mi:
        return "%dm %02ds" % (mi, int(se))
    return "%ds" % int(se)


def fmt_local(d, formato="%d/%m %H:%M"):
    return d.astimezone(TZ).strftime(formato) if d else ""


def ip_valido(texto):
    try:
        return str(ipaddress.ip_address((texto or "").strip()))
    except ValueError:
        return None


def origem_alerta(a):
    src = a.get("source") or {}
    return (src.get("ip") or src.get("value") or "?"), (src.get("cn") or "--"), (src.get("as_name") or "")


# ---------------------------------------------------------------- alertas e bloqueios
def compactar_alertas(alertas, limite=3000):
    """Uma linha por alerta, a mais nova primeiro."""
    out = []
    for a in alertas:
        if a.get("simulated"):
            continue
        ip, pais, asn = origem_alerta(a)
        q = parse_iso(a.get("start_at") or a.get("created_at"))
        decs = [d for d in (a.get("decisions") or []) if not d.get("simulated")]
        d0 = decs[0] if decs else {}
        exp = fmt_duracao(d0.get("duration")) if d0 else None
        out.append({"id": a.get("id"), "t": int(q.timestamp()) if q else 0, "quando": fmt_local(q), "ip": ip, "pais": pais,
                    "as": asn, "cenario": a.get("scenario") or "?", "eventos": int(a.get("events_count") or 0),
                    "decisao": d0.get("type") or "", "origem": d0.get("origin") or "",
                    "expira": exp or ("expirada" if d0 else "")})
    out.sort(key=lambda x: x["t"], reverse=True)
    return out[:limite]


def listar_bans(ativos):
    """Decisoes ainda em vigor (uma por valor), a partir dos alertas com decisao ativa."""
    bans, ja = [], set()
    for a in ativos:
        ip, pais, asn = origem_alerta(a)
        for d in a.get("decisions") or []:
            exp = fmt_duracao(d.get("duration"))
            valor = d.get("value") or ip
            if d.get("simulated") or exp is None or valor in ja:
                continue
            ja.add(valor)
            bans.append({"ip": valor, "pais": pais, "as": asn, "cenario": d.get("scenario") or a.get("scenario") or "?",
                         "tipo": d.get("type") or "ban", "origem": d.get("origin") or "", "escopo": d.get("scope") or "Ip",
                         "expira": exp, "restante_s": duracao_s(d.get("duration")) or 0,
                         "eventos": int(a.get("events_count") or 0), "alerta": a.get("id")})
    bans.sort(key=lambda b: -b["restante_s"])
    return bans


def variacao(atual, anterior):
    """Variacao percentual contra o periodo anterior; None quando nao ha base de comparacao (anterior == 0)."""
    if not anterior:
        return None
    return round(100.0 * (atual - anterior) / anterior)


def _hosts_alerta(a):
    """Hosts (target_fqdn) dos eventos que o CrowdSec guardou no alerta; vazio se a LAPI nao devolveu eventos."""
    hs = []
    for e in a.get("events") or []:
        for m in e.get("meta") or []:
            if m.get("key") == "target_fqdn" and m.get("value"):
                hs.append(str(m["value"])[:120].lower())
    return hs


def por_dominio(alertas, top=8):
    """Sites mais atacados. Cada alerta distribui o seu peso (1) entre os hosts dos seus eventos; assim um alerta
    com 3 eventos no siapi e 1 no ensino conta 0,75 e 0,25. Retorna (lista, disponivel): disponivel=False quando
    nenhum alerta trouxe eventos (ai o grafico nao tem como ser montado)."""
    c, algum = Counter(), False
    for a in alertas:
        if a.get("simulated"):
            continue
        hs = _hosts_alerta(a)
        if not hs:
            continue
        algum = True
        for h, n in Counter(hs).items():
            c[h] += n / len(hs)
    return [[h, round(v, 1) if v % 1 else int(v)] for h, v in c.most_common(top)], algum


def anomalia(serie, minimo=5, fator=3.0):
    """Pico recente: o maior dos dois ultimos baldes da serie contra a media dos demais. None se nao ha pico."""
    if len(serie) < 6:
        return None
    base, ult = serie[:-2], serie[-2:]
    media = sum(x["n"] for x in base) / len(base)
    pico = max(ult, key=lambda x: x["n"])
    if pico["n"] < minimo or pico["n"] < fator * max(media, 1.0):
        return None
    return {"quando": pico["d"], "n": pico["n"], "media": round(media, 1), "fator": round(pico["n"] / max(media, 1.0), 1)}


def reincidentes(alertas, banidos, top=10):
    """IPs com 2+ alertas no periodo, do que mais voltou ao que menos."""
    por_ip = {}
    for a in alertas:
        if a.get("simulated"):
            continue
        ip, pais, asn = origem_alerta(a)
        r = por_ip.setdefault(ip, {"ip": ip, "pais": pais, "as": asn, "alertas": 0, "cen": Counter(), "t": 0})
        r["alertas"] += 1
        r["cen"][a.get("scenario") or "?"] += 1
        q = parse_iso(a.get("start_at") or a.get("created_at"))
        if q:
            r["t"] = max(r["t"], int(q.timestamp()))
    lista = [r for r in por_ip.values() if r["alertas"] >= 2]
    lista.sort(key=lambda r: (-r["alertas"], -r["t"]))
    return len(lista), [{"ip": r["ip"], "pais": r["pais"], "as": r["as"], "alertas": r["alertas"],
                         "cenarios": [c for c, _ in r["cen"].most_common(2)],
                         "ultimo": fmt_local(datetime.fromtimestamp(r["t"], timezone.utc)) if r["t"] else "",
                         "banido": r["ip"] in banidos} for r in lista[:top]]


def _idade_ultimo(alertas, agora):
    ts = [parse_iso(a.get("start_at") or a.get("created_at")) for a in alertas if not a.get("simulated")]
    ts = [t for t in ts if t]
    return int(max(0, (agora - max(ts)).total_seconds())) if ts else None


def _comparar(kpis, anteriores):
    """Alertas, IPs e eventos do periodo contra o periodo imediatamente anterior, de mesma duracao."""
    if anteriores is None:
        return None
    ant = {"alertas": 0, "ips": set(), "eventos": 0}
    for a in anteriores:
        if a.get("simulated"):
            continue
        ant["alertas"] += 1
        ant["ips"].add(origem_alerta(a)[0])
        ant["eventos"] += int(a.get("events_count") or 0)
    ant["ips"] = len(ant["ips"])
    return {k: {"atual": kpis[k], "anterior": ant[k], "pct": variacao(kpis[k], ant[k])} for k in ("alertas", "ips", "eventos")}


def resumir(alertas, ativos, janela_h, agora=None, anteriores=None):
    agora = agora or datetime.now(timezone.utc)
    por_cen, por_pais, por_ip, por_as = Counter(), Counter(), Counter(), Counter()
    eventos, vistos, validos = 0, set(), 0
    passo_h = 1 if janela_h <= 48 else 24
    buckets, mapa = {}, [[0] * 24 for _ in range(7)]
    fim_local = agora.astimezone(TZ)
    if passo_h == 1:
        base = fim_local.replace(minute=0, second=0, microsecond=0)
        for i in range(janela_h):
            buckets[base - timedelta(hours=i)] = 0
    else:
        base = fim_local.replace(hour=0, minute=0, second=0, microsecond=0)
        for i in range(janela_h // 24):
            buckets[base - timedelta(days=i)] = 0
    for a in alertas:
        if a.get("simulated"):
            continue
        validos += 1
        ip, pais, asn = origem_alerta(a)
        quando = parse_iso(a.get("start_at") or a.get("created_at"))
        eventos += int(a.get("events_count") or 0)
        por_cen[a.get("scenario") or "?"] += 1
        por_pais[pais] += 1
        por_ip[ip] += 1
        por_as[asn or "(sem AS)"] += 1
        vistos.add(ip)
        if quando:
            loc = quando.astimezone(TZ)
            mapa[loc.weekday()][loc.hour] += 1
            chave = loc.replace(minute=0, second=0, microsecond=0) if passo_h == 1 else \
                loc.replace(hour=0, minute=0, second=0, microsecond=0)
            if chave in buckets:
                buckets[chave] += 1
    bans = listar_bans(ativos)
    banidos = {b["ip"] for b in bans}
    com_decisao = {origem_alerta(a)[0] for a in alertas if not a.get("simulated") and
                   any(not d.get("simulated") for d in (a.get("decisions") or []))}
    n_reinc, lista_reinc = reincidentes(alertas, banidos)
    serie = [{"r": k.strftime("%H:00") if passo_h == 1 else k.strftime("%d/%m"),
              "d": k.strftime("%d/%m %H:00") if passo_h == 1 else k.strftime("%d/%m"), "n": v}
             for k, v in sorted(buckets.items())]
    r = {
        "gerado_em": agora.astimezone(TZ).strftime("%d/%m/%Y %H:%M:%S"),
        "kpis": {"bans": len(bans), "alertas": validos, "ips": len(vistos), "paises": len(set(por_pais) - {"--"}),
                 "eventos": eventos},
        "bans": bans[:200], "alertas": compactar_alertas(alertas, 100), "serie": serie,
        "passo": "hora" if passo_h == 1 else "dia", "mapa": mapa,
        "top_cenarios": por_cen.most_common(8), "top_paises": por_pais.most_common(8), "top_ips": por_ip.most_common(8),
        "top_as": por_as.most_common(8),
        "funil": [["Alertas", validos], ["IPs distintos", len(vistos)], ["IPs com bloqueio", len(com_decisao)],
                  ["IPs reincidentes", n_reinc]],
        "reincidentes": lista_reinc, "n_reincidentes": n_reinc,
        "anomalia": anomalia([{"n": x["n"], "d": x["d"]} for x in serie]),
        "ultimo_alerta_ha_s": _idade_ultimo(alertas, agora),
    }
    d_dom, ok_dom = por_dominio(alertas)
    r["dominios"], r["dominios_ok"] = d_dom, ok_dom
    r["comparativo"] = _comparar(r["kpis"], anteriores)
    return r


def resumo_eventos(eventos, top=8):
    """O que o IP tentou: pedidos mais repetidos (metodo + caminho + status), programa usado e alvo."""
    pedidos, agentes, hosts = Counter(), Counter(), Counter()
    for e in eventos:
        req = ("%s %s" % (e.get("metodo") or "", e.get("caminho") or "")).strip()
        if req:
            pedidos[(req, e.get("status") or "")] += 1
        if e.get("ua") and e["ua"] != "-":
            agentes[e["ua"]] += 1
        if e.get("host"):
            hosts[e["host"]] += 1
    return {"top": [{"req": r, "status": s, "n": n} for (r, s), n in pedidos.most_common(top)],
            "agentes": agentes.most_common(3), "hosts": hosts.most_common(3), "distintos": len(pedidos)}


def detalhar(a, limite=200):
    """Eventos (as requisicoes) que dispararam um alerta + o JSON bruto, para conferir o que o CrowdSec guardou."""
    ip, pais, asn = origem_alerta(a)
    eventos = []
    for e in (a.get("events") or [])[:limite]:
        meta = {m.get("key"): str(m.get("value", ""))[:300] for m in (e.get("meta") or []) if m.get("key")}
        t = parse_iso(e.get("timestamp"))
        eventos.append({
            "quando": fmt_local(t, "%d/%m %H:%M:%S"),
            "metodo": meta.get("http_verb", ""), "caminho": meta.get("http_path", ""),
            "status": meta.get("http_status", ""), "host": meta.get("target_fqdn", ""), "ua": meta.get("user_agent", ""),
            "outros": ", ".join("%s=%s" % (k, v) for k, v in meta.items() if k not in META_PADRAO and k not in META_RUIDO)})
    ini, fim = parse_iso(a.get("start_at")), parse_iso(a.get("stop_at"))
    return {"id": a.get("id"), "cenario": a.get("scenario") or "?", "ip": ip, "pais": pais, "as": asn,
            "mensagem": a.get("message") or "", "maquina": a.get("machine_id") or "",
            "inicio": fmt_local(ini, "%d/%m/%Y %H:%M:%S"), "fim": fmt_local(fim, "%d/%m/%Y %H:%M:%S"),
            "total": int(a.get("events_count") or 0), "mostrados": len(eventos), "eventos": eventos,
            "resumo": resumo_eventos(eventos),
            "decisoes": [{"tipo": d.get("type") or "", "origem": d.get("origin") or "",
                          "expira": fmt_duracao(d.get("duration")) or "expirada"}
                         for d in (a.get("decisions") or []) if not d.get("simulated")],
            "bruto": json.dumps(a, ensure_ascii=False, indent=1)[:30000]}


def por_cenario(alertas):
    acc = {}
    for a in alertas:
        if a.get("simulated"):
            continue
        ip, pais, _ = origem_alerta(a)
        r = acc.setdefault(a.get("scenario") or "?", {"ips": set(), "alertas": 0, "eventos": 0, "t": 0, "paises": Counter()})
        r["alertas"] += 1
        r["ips"].add(ip)
        r["eventos"] += int(a.get("events_count") or 0)
        r["paises"][pais] += 1
        q = parse_iso(a.get("start_at") or a.get("created_at"))
        if q:
            r["t"] = max(r["t"], int(q.timestamp()))
    out = [{"nome": n, "alertas": r["alertas"], "ips": len(r["ips"]), "eventos": r["eventos"],
            "ultimo": fmt_local(datetime.fromtimestamp(r["t"], timezone.utc)) if r["t"] else "",
            "pais_top": r["paises"].most_common(1)[0][0] if r["paises"] else ""} for n, r in acc.items()]
    out.sort(key=lambda x: -x["alertas"])
    return out


def mesclar_cenarios(stats, instalados, buckets):
    """Junta o que disparou na janela (alertas), o que esta instalado (arquivos) e os contadores do motor (Prometheus)."""
    por_nome = {s["nome"]: s for s in stats}
    inst = {i["nome"]: i for i in instalados}
    bk = {c["nome"]: c for c in buckets}
    nomes = list(por_nome) + [n for n in inst if n not in por_nome]
    out = []
    for n in nomes:
        s = por_nome.get(n) or {"nome": n, "alertas": 0, "ips": 0, "eventos": 0, "ultimo": "", "pais_top": ""}
        i, c = inst.get(n, {}), bk.get(n, {})
        out.append(dict(s, instalado=n in inst, origem=i.get("origem", ""), descricao=i.get("descricao"), tipo=i.get("tipo"),
                        capacidade=i.get("capacidade"), leakspeed=i.get("leakspeed"), blackhole=i.get("blackhole"),
                        legivel=i.get("legivel", False), instanciados=c.get("instanciados", 0), overflow=c.get("overflow", 0)))
    return out


def consulta_ip(ip, alertas, decisoes):
    """Historico de um IP: alertas (da LAPI) + decisoes em vigor (da LAPI, via chave de bouncer, se houver)."""
    validos = [a for a in alertas if not a.get("simulated")]
    lista = compactar_alertas(validos, 200)
    cens = Counter(a.get("scenario") or "?" for a in validos)
    pais = asn = ""
    if validos:
        _, pais, asn = origem_alerta(validos[0])
    ts = [x["t"] for x in lista if x["t"]]
    decs = []
    for d in decisoes or []:
        exp = fmt_duracao(d.get("duration"))
        if d.get("simulated") or exp is None:
            continue
        decs.append({"tipo": d.get("type") or "", "origem": d.get("origin") or "", "cenario": d.get("scenario") or "",
                     "escopo": d.get("scope") or "", "valor": d.get("value") or "", "expira": exp})
    dias = Counter()
    for x in lista:
        if x["t"]:
            dias[datetime.fromtimestamp(x["t"], TZ).date()] += 1
    serie_dias = []
    if dias:
        d0, d1 = min(dias), max(dias)
        if (d1 - d0).days > 59:
            d0 = d1 - timedelta(days=59)
        for i in range((d1 - d0).days + 1):
            dia = d0 + timedelta(days=i)
            serie_dias.append({"r": dia.strftime("%d/%m"), "d": dia.strftime("%d/%m/%Y"), "n": dias.get(dia, 0)})
    hosts = Counter(h for a in validos for h in _hosts_alerta(a))
    return {"ip": ip, "pais": pais, "as": asn, "total_alertas": len(validos),
            "serie_dias": serie_dias, "sites": hosts.most_common(8),
            "total_eventos": sum(int(a.get("events_count") or 0) for a in validos),
            "primeiro": fmt_local(datetime.fromtimestamp(min(ts), timezone.utc), "%d/%m/%Y %H:%M") if ts else "",
            "ultimo": fmt_local(datetime.fromtimestamp(max(ts), timezone.utc), "%d/%m/%Y %H:%M") if ts else "",
            "cenarios": cens.most_common(), "alertas": lista, "decisoes": decs}


def _seguro(v):
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s  # evita injecao de formula no Excel


def csv_texto(cabecalho, linhas):
    """CSV para o Excel brasileiro: separador ';' e BOM UTF-8."""
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";", lineterminator="\r\n")
    w.writerow(cabecalho)
    for l in linhas:
        w.writerow([_seguro(c) for c in l])
    return "﻿" + buf.getvalue()


# ---------------------------------------------------------------- metricas do Prometheus (127.0.0.1:6060)
_PROM = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+(\S+)(?:\s+-?\d+)?$")
_LBL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')


def parse_prom(texto):
    """Formato de texto do Prometheus -> lista de (nome, {rotulos}, valor)."""
    out = []
    for linha in (texto or "").splitlines():
        linha = linha.strip()
        if not linha or linha.startswith("#"):
            continue
        m = _PROM.match(linha)
        if not m:
            continue
        try:
            v = float(m.group(3))
        except ValueError:
            continue
        rot = {k: val.replace('\\"', '"').replace("\\\\", "\\").replace("\\n", "\n") for k, val in _LBL.findall(m.group(2) or "")}
        out.append((m.group(1), rot, v))
    return out


def _agrupar(am, nome, *chaves):
    r = {}
    for n, rot, v in am:
        if n == nome:
            k = tuple(rot.get(c, "") for c in chaves)
            r[k] = r.get(k, 0) + v
    return r


def _quando_ts(ts, agora):
    if not ts or ts <= 0:
        return None
    return {"quando": datetime.fromtimestamp(ts, TZ).strftime("%d/%m %H:%M:%S"), "ha_s": int(max(0, agora - ts))}


def saude(am, agora=None):
    agora = agora if agora is not None else time.time()
    n = lambda nome: sum(_agrupar(am, nome, "x").values())
    info = [rot for nome, rot, _ in am if nome == "cs_info"]
    tipos = {rot.get("source", ""): rot.get("acquis_type", "") for nome, rot, _ in am if nome in ("cs_filesource_hits_total", "cs_journalctlsource_hits_total")}
    lidas = {**_agrupar(am, "cs_filesource_hits_total", "source"), **_agrupar(am, "cs_journalctlsource_hits_total", "source")}
    ok, ko = _agrupar(am, "cs_parser_hits_ok_total", "source"), _agrupar(am, "cs_parser_hits_ko_total", "source")
    wl = _agrupar(am, "cs_node_wl_hits_total", "source")
    fontes = []
    for (src,), total in lidas.items():
        o, k = ok.get((src,), 0), ko.get((src,), 0)
        fontes.append({"fonte": src, "nome": os.path.basename(src) or src, "tipo": tipos.get(src, ""), "lidas": int(total),
                       "ok": int(o), "ko": int(k), "whitelist": int(wl.get((src,), 0)),
                       "pct_ok": round(100.0 * o / (o + k), 1) if (o + k) else None})
    fontes.sort(key=lambda f: -f["lidas"])
    hits, hok, hko = (_agrupar(am, x, "name", "stage") for x in ("cs_node_hits_total", "cs_node_hits_ok_total", "cs_node_hits_ko_total"))
    parsers = sorted(({"nome": nm, "estagio": st, "hits": int(v), "ok": int(hok.get((nm, st), 0)), "ko": int(hko.get((nm, st), 0))}
                      for (nm, st), v in hits.items()), key=lambda p: -p["hits"])
    wls = sorted(({"nome": nm, "motivo": mt, "hits": int(v)} for (nm, mt), v in _agrupar(am, "cs_node_wl_hits_total", "name", "reason").items()),
                 key=lambda w: -w["hits"])
    inst, over = _agrupar(am, "cs_bucket_instantiation_total", "name"), _agrupar(am, "cs_bucket_overflowed_total", "name")
    under, poured = _agrupar(am, "cs_bucket_underflowed_total", "name"), _agrupar(am, "cs_bucket_poured_total", "name")
    atuais = _agrupar(am, "cs_buckets", "name")
    nomes = set(k[0] for d in (inst, over, under, poured, atuais) for k in d)
    cenarios = sorted(({"nome": nm, "instanciados": int(inst.get((nm,), 0)), "despejados": int(poured.get((nm,), 0)),
                        "overflow": int(over.get((nm,), 0)), "underflow": int(under.get((nm,), 0)), "ativos": int(atuais.get((nm,), 0))}
                       for nm in nomes), key=lambda c: (-c["overflow"], -c["despejados"]))
    decisoes = sorted(({"acao": a, "origem": o, "motivo": m, "n": int(v)}
                       for (a, o, m), v in _agrupar(am, "cs_active_decisions", "action", "origin", "reason").items()), key=lambda d: -d["n"])
    alertas = sorted(({"tipo": k, "motivo": m, "n": int(v)} for (k, m), v in _agrupar(am, "cs_alerts", "kind", "reason").items()), key=lambda d: -d["n"])
    beat = [{"maquina": (m[:8] + "…") if len(m) > 8 else m, **(_quando_ts(v, agora) or {"quando": "", "ha_s": None})}
            for (m,), v in _agrupar(am, "cs_machines_last_heartbeat_timestamp", "machine").items()]
    req = lambda nome, *c: sorted(({**dict(zip(c, k)), "n": int(v)} for k, v in _agrupar(am, nome, *c).items()), key=lambda r: -r["n"])
    feats = {rot.get("feature", ""): bool(v) for nome, rot, v in am if nome == "cs_features"}
    return {
        "versao": info[0].get("version", "") if info else "",
        "recursos": feats,
        "capi": _quando_ts(sum(_agrupar(am, "cs_capi_last_pull_timestamp", "x").values()), agora),
        "papi": _quando_ts(sum(_agrupar(am, "cs_papi_last_pull_timestamp", "x").values()), agora),
        "buckets_ativos": int(n("cs_buckets")), "postoverflow_descartados": int(n("cs_postoverflow_dropped_total")),
        "fontes": fontes, "parsers": parsers[:40], "whitelists": wls[:20], "cenarios": cenarios, "decisoes": decisoes,
        "alertas_locais": alertas, "heartbeat": beat,
        "lapi_rotas": req("cs_lapi_route_requests_total", "method", "route"),
        "lapi_maquinas": [{**r, "maquina": (r["machine"][:8] + "…") if len(r["machine"]) > 8 else r["machine"]}
                          for r in req("cs_lapi_machine_requests_total", "machine", "method", "route")][:30],
        "lapi_bouncers": req("cs_lapi_bouncer_requests_total", "bouncer", "method", "route"),
    }


def snapshot_fontes(am):
    """{fonte: (lidas, interpretadas, nao interpretadas)}: contadores ACUMULADOS desde que o CrowdSec iniciou."""
    lidas = {**_agrupar(am, "cs_filesource_hits_total", "source"), **_agrupar(am, "cs_journalctlsource_hits_total", "source")}
    ok, ko = _agrupar(am, "cs_parser_hits_ok_total", "source"), _agrupar(am, "cs_parser_hits_ko_total", "source")
    return {src: (lidas[(src,)], ok.get((src,), 0), ko.get((src,), 0)) for (src,) in lidas}


def delta_fontes(antigo, novo):
    """O que mudou entre dois snapshots. Se algum contador diminuiu, o CrowdSec reiniciou no meio: usa o valor novo inteiro."""
    out = {}
    for src, (l, o, k) in novo.items():
        l0, o0, k0 = antigo.get(src, (0, 0, 0))
        if l < l0 or o < o0 or k < k0:
            l0 = o0 = k0 = 0
        dl, do, dk = l - l0, o - o0, k - k0
        out[src] = {"lidas": int(dl), "ok": int(do), "ko": int(dk),
                    "pct_ok": round(100.0 * do / (do + dk), 1) if (do + dk) > 0 else None}
    return out


# ---------------------------------------------------------------- configuracao do CrowdSec (so leitura)
def _ler(caminho, limite=20000):
    try:
        with open(caminho, "rb") as f:
            return f.read(limite).decode("utf-8", "replace")
    except OSError:
        return None  # inexistente ou sem permissao (ex.: arquivos do hub e config.yaml)


def meta_yaml(texto):
    """Campos de topo de um yaml do hub, sem depender de biblioteca yaml."""
    r, linhas = {}, (texto or "").splitlines()
    for i, l in enumerate(linhas):
        m = re.match(r"^(name|description|type|capacity|leakspeed|blackhole|groupby|duration|reprocess|stage):\s*(.*)$", l)
        if not m:
            continue
        v = m.group(2).strip()
        if v[:1] in (">", "|"):  # bloco: pega a proxima linha indentada
            v = linhas[i + 1].strip() if i + 1 < len(linhas) else ""
        r[m.group(1)] = v.strip("\"'")
    return r


def _nome_hub(caminho_link):
    m = re.search(r"/hub/[^/]+/([^/]+)/([^/]+)\.ya?ml$", caminho_link or "")
    return "%s/%s" % (m.group(1), m.group(2)) if m else None


def _itens(pasta):
    out = []
    try:
        arquivos = sorted(f for f in os.listdir(pasta) if f.endswith((".yaml", ".yml")))
    except OSError:
        return out
    for f in arquivos:
        p = os.path.join(pasta, f)
        stem = re.sub(r"\.ya?ml$", "", f)
        alvo = os.readlink(p) if os.path.islink(p) else ""
        meta = meta_yaml(_ler(p))
        nome = meta.get("name") or _nome_hub(alvo) or stem
        out.append({"arquivo": f, "nome": nome, "origem": "hub" if alvo else "local", "descricao": meta.get("description"),
                    "tipo": meta.get("type"), "capacidade": meta.get("capacity"), "leakspeed": meta.get("leakspeed"),
                    "blackhole": meta.get("blackhole"), "legivel": bool(meta)})
    return out


def _lista(pasta):
    try:
        return sorted(os.listdir(pasta))
    except OSError:
        return []


def ler_config(raiz="/etc/crowdsec"):
    acq = []
    candidatos = [os.path.join(raiz, "acquis.yaml")] + [os.path.join(raiz, "acquis.d", f) for f in _lista(os.path.join(raiz, "acquis.d"))
                                                         if f.endswith((".yaml", ".yml"))]
    for p in candidatos:
        t = _ler(p, 4000)
        if t is not None:
            acq.append({"arquivo": os.path.relpath(p, raiz).replace(os.sep, "/"), "conteudo": t})
    por_estagio = lambda base: [{"estagio": s, "itens": _itens(os.path.join(raiz, base, s))}
                                for s in _lista(os.path.join(raiz, base)) if os.path.isdir(os.path.join(raiz, base, s))]
    return {"acquisicao": acq, "colecoes": _itens(os.path.join(raiz, "collections")),
            "cenarios": _itens(os.path.join(raiz, "scenarios")), "parsers": por_estagio("parsers"),
            "postoverflows": por_estagio("postoverflows")}
