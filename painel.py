#!/usr/bin/env python3
"""Sentinela: painel web para o CrowdSec. Leitura + UMA acao de escrita (liberar IP), login por LDAP/LDAPS.

Servidor HTTP minimo (stdlib) + ldap3 (instalado por pip ou apt, ou colocado em ./lib). Roda no host do proxy
reverso, fala com a LAPI do CrowdSec em 127.0.0.1:8080 e escuta so num IP interno (o proxy publica em HTTPS).
Configuracao 100% por variaveis de ambiente (ver .env.example). Compativel com Python 3.10+.
"""
import base64
import hashlib
import hmac
import html
import ipaddress
import json
import os
import random
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import dados as D
from dados import TZ, TZ_NOME, detalhar, fmt_duracao, parse_iso, resumir  # noqa: F401 (reexportados: os testes usam painel.X)

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE, "lib"))
STATIC = os.path.join(BASE, "static")
JANELAS = {"1h": 1, "24h": 24, "7d": 168, "30d": 720}
USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def env(nome, padrao=""):
    return os.environ.get(nome, padrao)


class Config:
    def __init__(self):
        self.bind = env("PAINEL_BIND", "127.0.0.1")
        self.port = int(env("PAINEL_PORT", "8088"))
        self.secret = env("PAINEL_SECRET").encode()
        self.lapi_url = env("LAPI_URL", "http://127.0.0.1:8080").rstrip("/")
        self.lapi_machine = env("LAPI_MACHINE", "painel")
        self.lapi_password = env("LAPI_PASSWORD")
        self.org = env("ORG_NOME").strip()  # nome da organizacao no titulo e no login (vazio = so "Sentinela")
        self.ldap_host = env("LDAP_HOST")
        self.ldap_port = int(env("LDAP_PORT", "636"))
        self.ldap_base = env("LDAP_BASE")  # ex.: ou=people,dc=exemplo,dc=com
        self.ldap_ca = env("LDAP_CA")  # certificado (CA) do servidor LDAP, fixado na conexao
        self.ldap_name = env("LDAP_NAME")  # nome DNS que consta no certificado (o ldap3 nao confere IP no SAN)
        # Molde do DN usado no bind. {usuario} = login digitado (ja escapado), {base} = LDAP_BASE.
        self.ldap_user_dn = env("LDAP_USER_DN", "uid={usuario},{base}")
        # Servidores LDAP. BROKER_A_* / BROKER_B_* (opcional, para dois servidores): o painel tenta primeiro o cuja rede
        # (BROKER_x_REDES) contem o IP de quem esta entrando e, se ele nao responder, o outro. Sem BROKER_*, usa o LDAP_*.
        self.brokers = []
        for k, nome_padrao in (("A", ""), ("B", "")):
            h = env("BROKER_%s_HOST" % k)
            if h:
                self.brokers.append({
                    "nome": env("BROKER_%s_NOME" % k, "Broker " + k), "host": h,
                    "port": int(env("BROKER_%s_PORT" % k, "636")),
                    "ca": env("BROKER_%s_CA" % k),
                    "name": env("BROKER_%s_NAME" % k, nome_padrao),
                    "redes": [ipaddress.ip_network(x.strip(), strict=False) for x in env("BROKER_%s_REDES" % k).split(",") if x.strip()]})
        if not self.brokers:
            self.brokers.append({"nome": "broker", "host": self.ldap_host, "port": self.ldap_port, "ca": self.ldap_ca,
                                 "name": self.ldap_name, "redes": []})
        self.allowed = {u.strip().lower() for u in env("ALLOWED_USERS", "").split(",") if u.strip()}
        # Acesso por grupo do LDAP: quem tiver este DN no memberOf entra. Ex.: cn=sentinela,ou=groups,dc=exemplo,dc=com
        self.allowed_group = env("ALLOWED_GROUP").strip().lower()
        self.idle = int(env("IDLE_SECONDS", "900"))
        self.max_life = int(env("MAX_LIFE_SECONDS", "28800"))
        # "Lembrar de mim": sessao mais longa em cookie persistente (0 dias = sem a opcao na tela de login)
        self.lembrar_dias = int(env("REMEMBER_DAYS", "7"))
        self.lembrar_max = self.lembrar_dias * 86400
        self.lembrar_idle = int(env("REMEMBER_IDLE_SECONDS", "86400"))
        self.cookie_secure = env("COOKIE_SECURE", "1") == "1"
        self.proxies = [ipaddress.ip_network(x.strip()) for x in
                        env("TRUSTED_PROXIES", "172.16.0.0/12").split(",") if x.strip()]
        self.demo = env("PAINEL_DEMO") == "1"
        # Liberar IP: so ativa com UNBAN_HASH. Quem pode liberar tambem passa a poder entrar no painel.
        self.unban_users = {u.strip().lower() for u in env("UNBAN_USERS").split(",") if u.strip()}
        self.unban_hash = env("UNBAN_HASH")
        self.estado = env("PAINEL_ESTADO")  # pasta gravavel (historico de liberacoes); vazio = so em memoria
        if self.demo and not self.unban_hash:
            self.unban_hash, self.unban_users = gerar_hash_senha("demo", 20000), self.unban_users | {"demo"}
        self.allowed = self.allowed | self.unban_users
        self.liberar_ativo = bool(self.unban_users and self.unban_hash)
        # Lista de IPs/redes que podem abrir o painel (vazia = sem restricao por IP). Ex.: 192.0.2.45,198.51.100.0/24
        self.allowed_nets = [ipaddress.ip_network(x.strip(), strict=False)
                             for x in env("ALLOWED_IPS").split(",") if x.strip()]
        self.bouncer_key = env("BOUNCER_KEY")  # opcional: habilita a consulta de decisoes (inclui lista da comunidade)
        self.prom_url = env("PROM_URL", "http://127.0.0.1:6060/metrics")
        self.config_dir = env("CROWDSEC_CONFIG_DIR", "/etc/crowdsec")
        self.titulo = (self.org + " · Sentinela") if self.org else "Sentinela"
        b = env("PAINEL_BASE").strip("/")
        self.base = "/" + b if b else ""  # ex.: /sentinela (publicado como subcaminho no proxy)


# ---------------------------------------------------------------- sessao (cookie assinado, sem estado)
def _b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def criar_token(secret, uid, nome, emitido, ultimo, lembrar=False):
    d = {"u": uid, "n": nome, "i": emitido, "l": ultimo}
    if lembrar:
        d["m"] = 1  # sessao "lembrar de mim": vale com os limites maiores (idle_m/max_m)
    corpo = _b64(json.dumps(d, separators=(",", ":")).encode())
    return corpo + "." + _b64(hmac.new(secret, corpo.encode(), hashlib.sha256).digest())


def ler_token(secret, token, idle, max_life, agora=None, idle_m=None, max_m=None):
    """Devolve o dict da sessao ou None (assinatura invalida, inativa demais ou velha demais).
    Sessao com "lembrar de mim" (m=1) usa os limites idle_m/max_m, quando informados."""
    agora = time.time() if agora is None else agora
    try:
        corpo, assinatura = token.split(".", 1)
        esperada = _b64(hmac.new(secret, corpo.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(esperada, assinatura):
            return None
        d = json.loads(_unb64(corpo))
        if d.get("m") and idle_m and max_m:
            idle, max_life = idle_m, max_m
        if agora - d["l"] > idle or agora - d["i"] > max_life:
            return None
        return d
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def gerar_hash_senha(senha, iteracoes=600000):
    """PBKDF2-SHA256 com sal aleatorio: 'pbkdf2_sha256:iteracoes:sal:hash' (a senha em si nunca e guardada)."""
    sal = os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), sal, iteracoes)
    return "pbkdf2_sha256:%d:%s:%s" % (iteracoes, _b64(sal), _b64(h))


def verificar_senha(senha, armazenado):
    """Compara em tempo constante. Hash ausente, mal formado ou com parametros absurdos = False."""
    try:
        alg, it, sal, h = (armazenado or "").split(":")
        it = int(it)
        if alg != "pbkdf2_sha256" or not 10000 <= it <= 5000000:
            return False
        esperado = _unb64(h)
        calc = hashlib.pbkdf2_hmac("sha256", (senha or "").encode("utf-8"), _unb64(sal), it, dklen=len(esperado))
        return hmac.compare_digest(calc, esperado)
    except (ValueError, TypeError):
        return False


class Auditoria:
    """Quem liberou qual IP, quando e por que. Fica em memoria (200 ultimos) e, se houver pasta, em liberacoes.jsonl."""

    def __init__(self, pasta="", maximo=200):
        self._l, self._itens, self.maximo = threading.Lock(), [], maximo
        self.arquivo = os.path.join(pasta, "liberacoes.jsonl") if pasta else ""
        if self.arquivo and os.path.isfile(self.arquivo):
            try:
                with open(self.arquivo, encoding="utf-8") as f:
                    for linha in f.readlines()[-maximo:]:
                        try:
                            self._itens.append(json.loads(linha))
                        except ValueError:
                            pass
            except OSError:
                pass

    def registrar(self, **campos):
        item = dict(campos, quando=datetime.now(TZ).strftime("%d/%m/%Y %H:%M:%S"), t=int(time.time()))
        with self._l:
            self._itens.append(item)
            del self._itens[:-self.maximo]
            if self.arquivo:
                try:
                    with open(self.arquivo, "a", encoding="utf-8") as f:
                        f.write(json.dumps(item, ensure_ascii=False) + "\n")
                except OSError as e:
                    print("auditoria: nao consegui gravar %s: %s" % (self.arquivo, e), flush=True)
        return item

    def lista(self, n=100):
        with self._l:
            return list(reversed(self._itens[-n:]))


def ip_permitido(redes, ip):
    """Sem lista = libera tudo. Com lista, so o que casar; IP ilegivel e negado."""
    if not redes:
        return True
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in r for r in redes)


# ---------------------------------------------------------------- anti forca bruta (por IP e por usuario)
class Limitador:
    def __init__(self, tentativas=5, janela=300):
        self.n, self.janela, self._f, self._l = tentativas, janela, {}, threading.Lock()

    def _podar(self, chave, agora):
        self._f[chave] = [t for t in self._f.get(chave, []) if agora - t < self.janela]
        return self._f[chave]

    def bloqueado(self, *chaves, agora=None):
        agora = time.time() if agora is None else agora
        with self._l:
            return any(len(self._podar(c, agora)) >= self.n for c in chaves)

    def falha(self, *chaves, agora=None):
        agora = time.time() if agora is None else agora
        with self._l:
            for c in chaves:
                self._podar(c, agora).append(agora)

    def ok(self, *chaves):
        with self._l:
            for c in chaves:
                self._f.pop(c, None)


# ---------------------------------------------------------------- autenticacao no broker (LDAPS, bind direto)
def escapar_rdn(valor):
    return re.sub(r'([,+"\\<>;=#])', r"\\\1", valor)


class LdapIndisponivel(Exception):
    pass


def ordenar_brokers(brokers, ip):
    """Brokers cuja rede contem o IP do cliente vem primeiro; os demais ficam de reserva, na ordem configurada."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return list(brokers)
    perto = [b for b in brokers if any(a in r for r in b["redes"])]
    return perto + [b for b in brokers if b not in perto]


def _autenticar_em(cfg, b, usuario, senha):
    from ldap3 import Connection, Server, Tls
    from ldap3.core.exceptions import LDAPBindError, LDAPException
    dn = cfg.ldap_user_dn.replace("{usuario}", escapar_rdn(usuario)).replace("{base}", cfg.ldap_base)
    # certificado fixado; o nome DNS do certificado e informado porque o ldap3 (Python 3.12) nao confere IP no SAN
    tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=b["ca"], valid_names=[b["name"]] if b["name"] else None)
    servidor = Server(b["host"], port=b["port"], use_ssl=True, tls=tls, connect_timeout=5)
    try:
        con = Connection(servidor, user=dn, password=senha, receive_timeout=8, raise_exceptions=True)
        if not con.bind():
            return False, None, ()
    except LDAPBindError:
        return False, None, ()
    except LDAPException as e:
        if "invalidcredentials" in str(e).lower().replace(" ", ""):
            return False, None, ()
        raise LdapIndisponivel(str(e))
    except OSError as e:
        raise LdapIndisponivel(str(e))
    nome, grupos = usuario, ()
    try:  # o usuario comum enxerga a propria entrada, com o memberOf (DNs dos grupos)
        if con.search(cfg.ldap_base, "(uid=%s)" % usuario.replace("\\", ""), attributes=["cn", "memberOf"]) and con.entries:
            e0 = con.entries[0]
            nome = str(e0.cn.value or usuario)
            grupos = tuple(str(g).strip().lower() for g in (e0.memberOf.values if "memberOf" in e0.entry_attributes else ()))
    except Exception:
        pass
    con.unbind()
    return True, nome, grupos


def autenticar(cfg, usuario, senha, ip="", log=None):
    """(True, nome, grupos) se um broker aceitou o bind; (False, None, ()) se credencial recusada.
    Levanta LdapIndisponivel se nenhum broker respondeu. Escolhe o broker pela rede do cliente (ip) e so passa ao
    outro se o primeiro estiver fora do ar: senha recusada e definitiva (os brokers se replicam). Senha vazia
    nunca vai ao servidor (bind LDAP com senha vazia e anonimo e 'funciona')."""
    if not USER_RE.match(usuario or "") or not senha:
        return False, None, ()
    ultimo = None
    for b in ordenar_brokers(cfg.brokers, ip):
        try:
            r = _autenticar_em(cfg, b, usuario, senha)
        except LdapIndisponivel as e:
            ultimo = e
            if log:
                log("broker %s (%s) indisponivel: %s" % (b["nome"], b["host"], e))
            continue
        if log:
            log("autenticacao pelo broker %s (%s) para o IP %s" % (b["nome"], b["host"], ip or "?"))
        return r
    raise LdapIndisponivel(str(ultimo) if ultimo else "nenhum broker configurado")


# ---------------------------------------------------------------- LAPI do CrowdSec (so GET)
class Lapi:
    def __init__(self, cfg):
        self.cfg, self._tok, self._exp, self._l = cfg, None, 0, threading.Lock()
        self._cache, self._cl = {}, threading.Lock()

    def _req(self, caminho, corpo=None, token=None, chave=None, metodo=None):
        r = urllib.request.Request(self.cfg.lapi_url + caminho, method=metodo or ("POST" if corpo is not None else "GET"))
        r.add_header("User-Agent", "sentinela/1")
        if corpo is not None:
            r.data = json.dumps(corpo).encode()
            r.add_header("Content-Type", "application/json")
        if token:
            r.add_header("Authorization", "Bearer " + token)
        if chave:
            r.add_header("X-Api-Key", chave)
        with urllib.request.urlopen(r, timeout=10) as resp:
            resposta = resp.read()
        return json.loads(resposta) if resposta.strip() else None

    def _login(self):
        d = self._req("/v1/watchers/login", {"machine_id": self.cfg.lapi_machine,
                                             "password": self.cfg.lapi_password, "scenarios": []})
        self._tok, self._exp = d["token"], time.time() + 45 * 60

    def _autenticado(self, caminho, metodo=None):
        with self._l:
            if not self._tok or time.time() > self._exp:
                self._login()
            try:
                return self._req(caminho, token=self._tok, metodo=metodo)
            except urllib.error.HTTPError as e:
                if e.code != 401:
                    raise
                self._login()
                return self._req(caminho, token=self._tok, metodo=metodo)

    def get(self, caminho):
        return self._autenticado(caminho)

    def liberar(self, ip):
        """UNICA operacao de escrita do painel: remove as decisoes em vigor do IP (DELETE /v1/decisions?ip=).
        'ip' ja foi validado por ipaddress (so digitos, ':', '.' e hex). Devolve quantas decisoes foram removidas."""
        d = self._autenticado("/v1/decisions?ip=%s" % ip, "DELETE")
        with self._cl:
            self._cache.clear()  # as listas passam a refletir a liberacao
        try:
            return int((d or {}).get("nbDeleted", 0))
        except (TypeError, ValueError):
            return 0

    def _cacheado(self, caminho, ttl=10):
        """As abas pedem as mesmas listas em sequencia: 10 s de cache poupam a LAPI sem esconder nada."""
        agora = time.time()
        with self._cl:
            c = self._cache.get(caminho)
            if c and agora - c[0] < ttl:
                return c[1]
        v = self.get(caminho) or []
        with self._cl:
            if len(self._cache) > 40:
                self._cache.clear()
            self._cache[caminho] = (agora, v)
        return v

    def alerta(self, id_):
        return self.get("/v1/alerts/%d" % id_)

    def alertas(self, horas, ativos=False):
        q = "/v1/alerts?include_capi=false&limit=5000&since=%dh" % horas
        if ativos:
            q += "&has_active_decision=true"
        return self._cacheado(q)

    def alertas_ip(self, ip):  # ip ja validado por ipaddress (so digitos, ':', '.', hex)
        return self.get("/v1/alerts?include_capi=false&limit=500&ip=%s" % ip) or []

    def decisoes_ip(self, ip):
        """Decisoes em vigor para o IP, inclusive as da lista da comunidade. Exige BOUNCER_KEY (None se nao houver)."""
        if not self.cfg.bouncer_key:
            return None
        return self._req("/v1/decisions?ip=%s" % ip, chave=self.cfg.bouncer_key) or []

    def prometheus(self):
        with urllib.request.urlopen(self.cfg.prom_url, timeout=6) as resp:
            return resp.read().decode("utf-8", "replace")


def dados_demo(janela_h):
    rnd = random.Random(7)
    agora = datetime.now(timezone.utc)
    cens = ["local/http-404-flood", "crowdsecurity/http-probing", "crowdsecurity/http-crawl-non_statics",
            "crowdsecurity/http-sensitive-files", "crowdsecurity/http-path-traversal-probing", "crowdsecurity/http-sqli-probing",
            "crowdsecurity/CVE-2022-26134"]
    pais = ["US", "BR", "RU", "CN", "NL", "DE", "IN", "VN"]
    ips = sorted({"%s.%d" % (rnd.choice(["192.0.2", "198.51.100", "203.0.113"]), rnd.randint(1, 254)) for _ in range(40)})
    al = []
    for i in range(min(900, janela_h * 9)):
        t = agora - timedelta(minutes=rnd.randint(0, janela_h * 60))
        k = rnd.randrange(len(ips))
        al.append({"id": i, "scenario": rnd.choices(cens, [5, 6, 3, 2, 1, 1, 1])[0], "events_count": rnd.randint(11, 400),
                   "start_at": t.isoformat(), "created_at": t.isoformat(),
                   "source": {"ip": ips[k], "cn": pais[k % len(pais)], "as_name": "AS%d Exemplo" % (1000 + k)},
                   "events": [{"timestamp": (t + timedelta(seconds=j)).isoformat(), "meta": [
                       {"key": "http_verb", "value": "GET"}, {"key": "http_status", "value": "404"},
                       {"key": "http_path", "value": rnd.choice(["/wp-login.php", "/.env", "/lib/tinymce/js/x.js", "/etc/passwd"])},
                       {"key": "target_fqdn", "value": "app.exemplo.com"},
                       {"key": "user_agent", "value": "Mozilla/5.0 (demo)"}, {"key": "source_ip", "value": ips[k]}]}
                       for j in range(min(12, 1 + i % 12))],
                   "decisions": [{"type": "ban", "value": ips[k], "duration": "%dh%dm%ds" % (rnd.randint(0, 3), rnd.randint(1, 59), rnd.randint(1, 59)),
                                  "scenario": "demo", "origin": "crowdsec"}]})
    at = [a for a in al[:14]]
    return al, at


# ---------------------------------------------------------------- HTTP
HEAD_SEG = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
                               "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin", "X-Frame-Options": "DENY",
}
TIPOS = {".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".png": "image/png",
         ".svg": "image/svg+xml"}

PAG_LOGIN = """<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>%(titulo)s</title>
<link rel="icon" type="image/png" href="%(base)s/static/favicon.png">
<link rel="stylesheet" href="%(base)s/static/app.css"></head>
<body class="login-ui" data-base="%(base)s"><main class="login-dialog">
<img class="logo" src="%(base)s/static/logo.png" alt="Logotipo">
<h1 class="app-name">%(titulo)s</h1>
<p class="aviso">Entre com seu usuário e senha da sua conta.</p>
%(erro)s
<form method="post" action="%(base)s/login" autocomplete="on">
<label for="u">Usuário</label><input id="u" name="usuario" type="text" autocomplete="username" autocapitalize="none" autofocus required maxlength="64">
<label for="s">Senha</label><input id="s" name="senha" type="password" autocomplete="current-password" required maxlength="256">
%(lembrar)s<button type="submit">Entrar</button></form></main>
<p class="rodape">Painel somente leitura · Acesso restrito à equipe autorizada</p></body></html>"""

PAG_PAINEL = """<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>%(titulo)s</title>
<link rel="icon" type="image/png" href="%(base)s/static/favicon.png">
<link rel="stylesheet" href="%(base)s/static/app.css"></head><body class="painel" data-base="%(base)s">
<header class="topo"><img src="%(base)s/static/logo.png" alt="" class="topo-logo"><div class="topo-tit"><strong>%(titulo)s</strong>
<span>Defesa da rede · CrowdSec</span></div><div class="topo-dir">
<label class="sel"><span>Período</span><select id="janela"><option value="1h">1 hora</option><option value="24h" selected>24 horas</option>
<option value="7d">7 dias</option><option value="30d">30 dias</option></select></label>
<span class="usuario" title="Sessão">%(nome)s</span>
<form method="post" action="%(base)s/logout"><button class="sair" type="submit">Sair</button></form></div></header>
<nav class="abas" id="abas" aria-label="Seções">
<button type="button" data-aba="geral" class="ativa">Visão geral</button><button type="button" data-aba="alertas">Alertas</button>
<button type="button" data-aba="bloqueios">Bloqueios</button><button type="button" data-aba="ip">Consultar IP</button>
<button type="button" data-aba="cenarios">Cenários</button><button type="button" data-aba="saude">Saúde do CrowdSec</button>
<button type="button" data-aba="config">Configuração</button></nav>
<div id="aviso" class="erro aviso-topo" hidden></div>

<main class="aba grade" id="aba-geral"><section class="kpis" id="kpis"></section>
<section class="pico" id="pico" role="status" hidden></section>
<section class="cartao dois"><h2>Alertas por <span id="passo">hora</span></h2><div id="grafico"></div></section>
<section class="cartao"><h2>Alertas por cenário <small>(proporção)</small></h2><div id="rosca"></div></section>
<section class="cartao"><h2>Principais cenários</h2><div id="top-cen"></div></section>
<section class="cartao"><h2>Países de origem</h2><div id="top-pais"></div></section>
<section class="cartao"><h2>IPs mais ativos</h2><div id="top-ip"></div></section>
<section class="cartao larg"><h2>Redes (AS) mais ativas</h2><div id="top-as"></div></section>
<section class="cartao" id="card-dom"><h2>Sites mais atacados <small id="n-dom"></small></h2><div id="top-dom"></div></section>
<section class="cartao"><h2>Funil do período <small>(do alerta ao bloqueio)</small></h2><div id="funil"></div></section>
<section class="cartao larg"><h2>Reincidentes <small id="n-reinc"></small></h2><div class="rolagem"><table id="t-reinc"></table></div></section>
<section class="cartao larg" id="card-mapa" hidden><h2>Quando os ataques acontecem <small>(dia da semana × hora, fuso %(fuso)s)</small></h2><div id="mapa"></div></section>
<section class="cartao larg"><h2>Bloqueios ativos <small id="n-bans"></small></h2><div class="rolagem"><table id="t-bans"></table></div></section>
<section class="cartao larg"><h2>Alertas recentes <small>(100 mais novos; veja todos na aba Alertas)</small></h2><div class="rolagem"><table id="t-alertas"></table></div></section></main>

<main class="aba pagina" id="aba-alertas" hidden><section class="cartao larg"><h2>Todos os alertas do período</h2>
<div class="filtros"><input id="a-q" type="search" placeholder="Filtrar por IP, cenário, país ou rede…" aria-label="Filtrar alertas">
<select id="a-cen" aria-label="Cenário"><option value="">Todos os cenários</option></select>
<select id="a-pais" aria-label="País"><option value="">Todos os países</option></select>
<a id="csv-alertas" class="botao" href="#" download>Exportar CSV</a></div>
<p class="nota" id="n-alertas"></p><div class="rolagem alta"><table id="t-alertas-full"></table></div></section></main>

<main class="aba pagina" id="aba-bloqueios" hidden><section class="kpis" id="b-kpis"></section>
<section class="cartao larg"><h2>Bloqueios em vigor</h2>
<div class="filtros"><input id="b-q" type="search" placeholder="Filtrar por IP, cenário, país ou rede…" aria-label="Filtrar bloqueios">
<select id="b-tipo" aria-label="Ação"><option value="">Todas as ações</option></select>
<select id="b-origem" aria-label="Origem"><option value="">Todas as origens</option></select>
<a id="csv-bloqueios" class="botao" href="#" download>Exportar CSV</a></div>
<p class="nota" id="n-bloq"></p><div class="rolagem alta"><table id="t-bloqueios"></table></div></section>
<section class="cartao larg" id="b-liberar" hidden><h2>Liberar um IP</h2>
<form id="form-liberar" class="filtros"><input id="lib-ip" type="text" placeholder="IP a liberar, ex.: 187.255.176.5" aria-label="IP a liberar" maxlength="45" autocomplete="off">
<button type="submit" class="botao">Liberar…</button></form>
<p class="nota">Remove os bloqueios em vigor deste IP. Pede a senha de liberação e um motivo, e fica registrado abaixo. Se o IP continuar agindo como atacante, será bloqueado de novo.</p></section>
<section class="cartao larg"><h2>Histórico de liberações</h2><p class="nota" id="n-lib"></p><div class="rolagem"><table id="t-liberacoes"></table></div></section></main>

<main class="aba pagina" id="aba-ip" hidden><section class="cartao larg"><h2>Consultar um IP</h2>
<form id="form-ip" class="filtros"><input id="ip-q" type="text" inputmode="text" placeholder="Ex.: 177.177.158.14 ou 2001:db8::1" aria-label="Endereço IP" maxlength="45" autocomplete="off">
<button type="submit" class="botao">Consultar</button></form>
<p class="nota">Mostra todos os alertas que o CrowdSec guardou para o endereço, os cenários que ele acionou e se há bloqueio em vigor.</p></section>
<div id="ip-res"></div></main>

<main class="aba pagina" id="aba-cenarios" hidden><section class="cartao larg"><h2>Cenários de detecção</h2>
<p class="nota" id="cen-nota"></p><div class="rolagem alta"><table id="t-cenarios"></table></div></section></main>

<main class="aba grade" id="aba-saude" hidden><section class="kpis" id="s-kpis"></section>
<section class="cartao larg"><h2>Fontes de log <small>(o que o CrowdSec está lendo)</small></h2>
<p class="nota" id="s-nota"></p><div class="rolagem"><table id="s-fontes"></table></div></section>
<section class="cartao larg"><h2>Cenários no motor <small>(desde que o serviço iniciou)</small></h2><div class="rolagem"><table id="s-cen"></table></div></section>
<section class="cartao larg"><h2>Decisões em vigor no motor</h2><div class="rolagem"><table id="s-dec"></table></div></section>
<section class="cartao larg"><h2>Parsers</h2><div class="rolagem"><table id="s-parsers"></table></div></section>
<section class="cartao larg"><h2>Whitelists acionadas</h2><div class="rolagem"><table id="s-wl"></table></div></section>
<section class="cartao larg"><h2>API local (LAPI)</h2><div class="rolagem"><table id="s-lapi"></table></div></section>
<section class="cartao"><h2>Máquinas</h2><div class="rolagem"><table id="s-maq"></table></div></section>
<section class="cartao"><h2>Bouncers</h2><div class="rolagem"><table id="s-bou"></table></div></section>
<section class="cartao"><h2>Heartbeat</h2><div class="rolagem"><table id="s-hb"></table></div></section></main>

<main class="aba pagina" id="aba-config" hidden>
<section class="cartao larg"><h2>Fontes de log configuradas</h2><div id="c-acq"></div></section>
<section class="cartao larg"><h2>Coleções instaladas</h2><div class="rolagem"><table id="c-col"></table></div></section>
<section class="cartao larg"><h2>Parsers e enriquecimento</h2><div id="c-par"></div></section>
<section class="cartao larg"><h2>Pós-overflow <small>(whitelists e enriquecimento depois do disparo)</small></h2><div id="c-pos"></div></section>
<p class="nota">Somente leitura: o painel lê os arquivos de /etc/crowdsec que o sistema deixa visíveis; o config.yaml e as credenciais são protegidos e não aparecem aqui.</p></main>

<div id="modal" class="modal" hidden></div><footer class="rodape-p">Atualiza a cada 30 s · <span id="atualizado">—</span> · fuso %(fuso)s</footer>
<script src="%(base)s/static/glossario.js"></script><script src="%(base)s/static/app.js"></script></body></html>"""


class Historico:
    """Amostras dos contadores do CrowdSec (uma por minuto, em memoria, ~1 h). Os contadores do Prometheus sao
    acumulados desde que o servico iniciou; so comparando duas amostras se sabe o que aconteceu NO periodo."""

    def __init__(self, maximo=70):
        self._l, self._a, self.maximo = threading.Lock(), [], maximo

    def registrar(self, snap, ts=None):
        with self._l:
            self._a.append((time.time() if ts is None else ts, snap))
            del self._a[:-self.maximo]

    def recente(self, minutos=60):
        """{'minutos': janela real, 'fontes': {fonte: delta}} ou None enquanto so ha uma amostra."""
        with self._l:
            if len(self._a) < 2:
                return None
            novo = self._a[-1]
            base = next((a for a in self._a if a[0] >= novo[0] - minutos * 60), self._a[0])
            if base is novo:
                return None
            return {"minutos": int(round((novo[0] - base[0]) / 60)), "fontes": D.delta_fontes(base[1], novo[1])}


def amostrar(sv, intervalo=60):
    """Thread de fundo: guarda um snapshot das metricas a cada minuto, mesmo com ninguem olhando a tela."""
    while True:
        try:
            sv.hist.registrar(D.snapshot_fontes(D.parse_prom(sv.lapi.prometheus())))
        except Exception as e:
            print("amostrador: %s" % e, flush=True)
        time.sleep(intervalo)


class Servico:
    def __init__(self, cfg):
        self.cfg, self.lapi, self.lim, self.hist = cfg, Lapi(cfg), Limitador(), Historico()
        self.lim_lib, self.aud = Limitador(3, 600), Auditoria(cfg.estado)  # liberar IP: 3 erros de senha em 10 min travam
        if cfg.demo:  # demonstracao: uma amostra de 30 min atras em que o acumulado era menor e nada tinha falhado desde entao
            try:
                with open(os.path.join(BASE, "tests_data", "metricas_exemplo.txt"), encoding="utf-8") as f:
                    atual = D.snapshot_fontes(D.parse_prom(f.read()))
                self.hist.registrar({s: (int(l * 0.9), int(o * 0.9), k) for s, (l, o, k) in atual.items()}, time.time() - 1800)
            except OSError:
                pass


def criar_handler(sv):
    cfg = sv.cfg

    class H(BaseHTTPRequestHandler):
        server_version = "sentinela"
        sys_version = ""

        def log_message(self, fmt, *a):
            pass

        def _ip(self):
            ip = self.client_address[0]
            try:
                if any(ipaddress.ip_address(ip) in n for n in cfg.proxies):
                    return self.headers.get("X-Real-IP") or (self.headers.get("X-Forwarded-For", "").split(",")[-1].strip() or ip)
            except ValueError:
                pass
            return ip

        def _log(self, msg):
            print("%s ip=%s %s" % (datetime.now(TZ).strftime("%Y-%m-%d %H:%M:%S"), self._ip(), msg), flush=True)

        def _enviar(self, codigo, corpo, tipo="text/html; charset=utf-8", extra=None, cache=True):
            if isinstance(corpo, str):
                corpo = corpo.encode()
            self.send_response(codigo)
            self.send_header("Content-Type", tipo)
            self.send_header("Content-Length", str(len(corpo)))
            self.send_header("Cache-Control", "public, max-age=300" if cache else "no-store")
            for k, v in HEAD_SEG.items():
                self.send_header(k, v)
            for k, v in (extra or []):
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(corpo)

        def _redir(self, destino, extra=None):
            self.send_response(303)
            self.send_header("Location", cfg.base + destino)
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or []):
                self.send_header(k, v)
            self.end_headers()

        def _cookie(self, valor, apagar=False, max_age=None):
            c = "sentinela_sessao=%s; Path=%s; HttpOnly; SameSite=Strict" % ("" if apagar else valor, cfg.base or "/")
            if apagar:
                c += "; Max-Age=0"
            elif max_age:
                c += "; Max-Age=%d" % max_age  # persistente ("lembrar de mim"); sem isso o cookie some ao fechar o navegador
            if cfg.cookie_secure:
                c += "; Secure"
            return ("Set-Cookie", c)

        def _sessao(self):
            c = SimpleCookie(self.headers.get("Cookie", ""))
            if "sentinela_sessao" not in c:
                return None
            return ler_token(cfg.secret, c["sentinela_sessao"].value, cfg.idle, cfg.max_life,
                             idle_m=cfg.lembrar_idle if cfg.lembrar_dias else None, max_m=cfg.lembrar_max if cfg.lembrar_dias else None)

        def _renovar(self, s):
            agora = int(time.time())
            lembrar = bool(s.get("m"))
            resta = max(1, s["i"] + cfg.lembrar_max - agora) if lembrar else None
            return self._cookie(criar_token(cfg.secret, s["u"], s["n"], s["i"], agora, lembrar), max_age=resta)

        def _origem_ok(self):
            o = self.headers.get("Origin")
            if not o or o == "null":  # 'null' = navegador omitiu a origem; cai no Referer / Sec-Fetch-Site
                o = self.headers.get("Referer")
            if o:
                return urlparse(o).netloc == self.headers.get("Host", "")
            return self.headers.get("Sec-Fetch-Site", "same-origin") in ("same-origin", "none")

        def _login_pag(self, erro="", codigo=200):
            msg = '<p class="erro" role="alert">%s</p>' % html.escape(erro) if erro else ""
            lembrar = ('<label class="lembrar"><input type="checkbox" name="lembrar" value="1"> Lembrar de mim neste computador '
                       '(%d dias)</label>' % cfg.lembrar_dias) if cfg.lembrar_dias else ""
            self._enviar(codigo, PAG_LOGIN % {"erro": msg, "base": cfg.base, "lembrar": lembrar, "titulo": html.escape(cfg.titulo)}, cache=False)

        # ---- rotas
        def _ip_ok(self):
            return ip_permitido(cfg.allowed_nets, self._ip())

        def _negar_ip(self):
            self._log("acesso negado (IP fora da lista)")
            self._enviar(403, "Acesso não permitido a partir deste endereço.", "text/plain; charset=utf-8", cache=False)

        def _rota(self):
            p = urlparse(self.path)
            caminho = p.path
            if cfg.base and (caminho == cfg.base or caminho.startswith(cfg.base + "/")):
                caminho = caminho[len(cfg.base):] or "/"
            return p, caminho

        def do_GET(self):
            p, caminho = self._rota()
            if caminho != "/saude" and not self._ip_ok():
                return self._negar_ip()
            if caminho == "/saude":
                return self._enviar(200, '{"ok":true}', "application/json", cache=False)
            if caminho.startswith("/static/"):
                nome = os.path.basename(caminho)
                ext = os.path.splitext(nome)[1]
                arq = os.path.join(STATIC, nome)
                if ext in TIPOS and os.path.isfile(arq):
                    with open(arq, "rb") as f:
                        return self._enviar(200, f.read(), TIPOS[ext], cache=False)
                return self._enviar(404, "não encontrado", "text/plain; charset=utf-8", cache=False)
            s = self._sessao()
            if caminho == "/login":
                return self._redir("/") if s else self._login_pag()
            if not s:
                if caminho.startswith("/api/"):
                    return self._enviar(401, '{"erro":"sessao"}', "application/json", cache=False)
                return self._redir("/login")
            if caminho.startswith("/api/"):
                return self._api(s, caminho, parse_qs(p.query))
            if caminho == "/":
                return self._enviar(200, PAG_PAINEL % {"nome": html.escape(s["n"]), "base": cfg.base, "titulo": html.escape(cfg.titulo), "fuso": html.escape(TZ_NOME)}, cache=False, extra=[self._renovar(s)])
            self._enviar(404, "não encontrado", "text/plain; charset=utf-8", cache=False)

        # ---- API (todas so leitura). Cada _r_* devolve (codigo, corpo, tipo, cabecalhos extras).
        def _json(self, obj, codigo=200):
            return codigo, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8", []

        def _csv(self, nome, cabecalho, linhas):
            return 200, D.csv_texto(cabecalho, linhas), "text/csv; charset=utf-8", \
                [("Content-Disposition", 'attachment; filename="%s"' % nome)]

        def _alertas(self, horas, ativos=False):
            if cfg.demo:
                al, at = dados_demo(horas)
                return at if ativos else al
            return sv.lapi.alertas(horas, ativos=ativos)

        def _prom(self):
            if cfg.demo:
                with open(os.path.join(BASE, "tests_data", "metricas_exemplo.txt"), encoding="utf-8") as f:
                    return f.read()
            return sv.lapi.prometheus()

        def _config_dir(self):
            return os.path.join(BASE, "tests_data", "etc-crowdsec") if cfg.demo else cfg.config_dir

        def _r_resumo(self, q, horas):
            agora = datetime.now(timezone.utc)
            corte = agora - timedelta(hours=horas)
            todos = self._alertas(horas * 2)  # periodo atual + o imediatamente anterior, de mesma duracao
            atuais, ant = [], []
            for a in todos:
                t = D.parse_iso(a.get("start_at") or a.get("created_at"))
                (atuais if (t is None or t >= corte) else ant).append(a)
            r = resumir(atuais, self._alertas(horas, True), horas, agora, ant)
            r["comparativo_completo"] = len(todos) < 5000  # a LAPI devolve no maximo 5000 alertas
            return self._json(r)

        def _r_alerta(self, q, horas):
            id_ = (q.get("id") or [""])[0]
            if not re.fullmatch(r"\d{1,10}", id_):
                return self._json({"erro": "id invalido"}, 400)
            if cfg.demo:
                al, at = dados_demo(24)
                a = next((x for x in al + at if str(x["id"]) == id_), None)
            else:
                a = sv.lapi.alerta(int(id_))
            return self._json(detalhar(a)) if a else self._json({"erro": "alerta nao encontrado"}, 404)

        def _r_alertas(self, q, horas):
            lista = D.compactar_alertas(self._alertas(horas), 3000)
            return self._json({"alertas": lista, "cenarios": sorted({x["cenario"] for x in lista}),
                               "paises": sorted({x["pais"] for x in lista}),
                               "gerado_em": datetime.now(TZ).strftime("%d/%m/%Y %H:%M:%S")})

        def _r_alertas_csv(self, q, horas):
            j = (q.get("janela") or ["24h"])[0]
            lista = D.compactar_alertas(self._alertas(horas), 3000)
            return self._csv("alertas-%s.csv" % (j if j in JANELAS else "24h"),
                             ["Quando (horario local)", "IP", "Pais", "Rede (AS)", "Cenario", "Eventos", "Decisao", "Origem da decisao", "Expira em", "ID"],
                             [[x["quando"], x["ip"], x["pais"], x["as"], x["cenario"], x["eventos"], x["decisao"], x["origem"], x["expira"], x["id"]]
                              for x in lista])

        def _r_bloqueios(self, q, horas):
            return self._json({"bans": D.listar_bans(self._alertas(720, True)), "pode_liberar": self._pode_liberar(),
                               "gerado_em": datetime.now(TZ).strftime("%d/%m/%Y %H:%M:%S")})

        def _r_bloqueios_csv(self, q, horas):
            return self._csv("bloqueios.csv", ["IP/Valor", "Escopo", "Acao", "Origem", "Cenario", "Pais", "Rede (AS)", "Eventos", "Expira em", "Alerta"],
                             [[b["ip"], b["escopo"], b["tipo"], b["origem"], b["cenario"], b["pais"], b["as"], b["eventos"], b["expira"], b["alerta"]]
                              for b in D.listar_bans(self._alertas(720, True))])

        def _r_ip(self, q, horas):
            ip = D.ip_valido((q.get("ip") or [""])[0])
            if not ip:
                return self._json({"erro": "Informe um endereço IP válido (IPv4 ou IPv6)."}, 400)
            if cfg.demo:
                al, _ = dados_demo(720)
                alertas, decs = [a for a in al if a["source"]["ip"] == ip], None
            else:
                alertas, decs = sv.lapi.alertas_ip(ip), sv.lapi.decisoes_ip(ip)
            r = D.consulta_ip(ip, alertas, decs)
            r["decisoes_consultadas"] = decs is not None
            r["pode_liberar"] = self._pode_liberar()
            return self._json(r)

        def _r_cenarios(self, q, horas):
            stats = D.por_cenario(self._alertas(horas))
            inst = D.ler_config(self._config_dir())["cenarios"]
            try:
                buckets = D.saude(D.parse_prom(self._prom()))["cenarios"]
            except Exception as e:
                self._log("prometheus indisponivel: %s" % e)
                buckets = []
            return self._json({"cenarios": D.mesclar_cenarios(stats, inst, buckets), "metricas": bool(buckets),
                               "hub_legivel": any(i["legivel"] for i in inst if i["origem"] == "hub")})

        def _r_saude(self, q, horas):
            am = D.parse_prom(self._prom())
            d = D.saude(am)
            sv.hist.registrar(D.snapshot_fontes(am))  # inclui o instante atual na comparacao
            rec = sv.hist.recente(60)
            d["recente_minutos"] = rec["minutos"] if rec else 0
            for f in d["fontes"]:
                r = rec["fontes"].get(f["fonte"]) if rec else None
                f["r_lidas"], f["r_ko"], f["r_pct"] = (r["lidas"], r["ko"], r["pct_ok"]) if r else (None, None, None)
            return self._json(d)

        def _r_config(self, q, horas):
            c = D.ler_config(self._config_dir())
            c["hub_legivel"] = any(i["legivel"] for i in c["cenarios"] if i["origem"] == "hub")
            return self._json(c)

        def _pode_liberar(self):
            return cfg.liberar_ativo and getattr(self, "_uid", "") in cfg.unban_users

        def _r_liberacoes(self, q, horas):
            return self._json({"itens": sv.aud.lista(100), "ativo": cfg.liberar_ativo, "pode": self._pode_liberar()})

        def _corpo_json(self):
            try:
                d = json.loads(self._corpo.decode("utf-8", "replace") or "{}")
            except ValueError:
                return None
            return d if isinstance(d, dict) else None

        def _liberar(self):
            """POST /api/liberar {ip, motivo, senha}. Camadas: sessao LDAP, lista UNBAN_USERS, senha (hash),
            limite de tentativas, IP unico e valido, motivo obrigatorio, tudo registrado."""
            s = self._sessao()
            if not s:
                return self._enviar(401, '{"erro":"sessao"}', "application/json", cache=False)
            extra = [self._renovar(s)]  # acao do usuario: estende a sessao

            def resp(codigo, obj):
                return self._enviar(codigo, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8", extra=extra, cache=False)

            uid, ip_origem, d = s["u"].lower(), self._ip(), self._corpo_json()
            if d is None:
                return resp(400, {"erro": "Pedido inválido."})
            if not cfg.liberar_ativo:
                return resp(403, {"erro": "A liberação de IPs não está ativada neste servidor (falta definir a senha de liberação)."})
            if uid not in cfg.unban_users:
                self._log("liberar negado (usuario sem permissao) uid=%s" % uid)
                return resp(403, {"erro": "Seu usuário não tem permissão para liberar IPs."})
            chaves = ("l:i:" + ip_origem, "l:u:" + uid)
            alvo, motivo = D.ip_valido(str(d.get("ip", ""))), str(d.get("motivo", "")).strip()
            if sv.lim_lib.bloqueado(*chaves):
                self._log("liberar bloqueado (muitas tentativas) uid=%s" % uid)
                return resp(429, {"erro": "Muitas tentativas de senha. Aguarde alguns minutos."})
            if not alvo:
                return resp(400, {"erro": "Informe um endereço IP válido (um único endereço, não uma faixa)."})
            if not 5 <= len(motivo) <= 200:
                return resp(400, {"erro": "Informe o motivo da liberação (de 5 a 200 caracteres)."})
            if not verificar_senha(str(d.get("senha", "")), cfg.unban_hash):
                sv.lim_lib.falha(*chaves)
                time.sleep(0.7)
                sv.aud.registrar(usuario=uid, ip_origem=ip_origem, alvo=alvo, motivo=motivo, removidos=0, resultado="senha incorreta")
                self._log("liberar: SENHA INCORRETA uid=%s alvo=%s" % (uid, alvo))
                return resp(403, {"erro": "Senha de liberação incorreta."})
            try:
                removidos = 1 if cfg.demo else sv.lapi.liberar(alvo)
            except Exception as e:
                sv.aud.registrar(usuario=uid, ip_origem=ip_origem, alvo=alvo, motivo=motivo, removidos=0, resultado="erro na API")
                self._log("liberar: erro na LAPI uid=%s alvo=%s: %s" % (uid, alvo, e))
                return resp(502, {"erro": "Não foi possível falar com o CrowdSec. Nada foi alterado."})
            sv.lim_lib.ok(*chaves)
            sv.aud.registrar(usuario=uid, ip_origem=ip_origem, alvo=alvo, motivo=motivo, removidos=removidos, resultado="liberado")
            self._log("LIBERACAO uid=%s alvo=%s removidos=%d motivo=%r" % (uid, alvo, removidos, motivo))
            return resp(200, {"ok": True, "ip": alvo, "removidos": removidos})

        def _api(self, s, caminho, q):
            self._uid = s["u"].lower()
            rotas = {"/api/resumo": self._r_resumo, "/api/alerta": self._r_alerta, "/api/alertas": self._r_alertas,
                     "/api/alertas.csv": self._r_alertas_csv, "/api/bloqueios": self._r_bloqueios,
                     "/api/bloqueios.csv": self._r_bloqueios_csv, "/api/ip": self._r_ip, "/api/cenarios": self._r_cenarios,
                     "/api/saude": self._r_saude, "/api/config": self._r_config,
                     "/api/liberacoes": self._r_liberacoes}
            fn = rotas.get(caminho)
            if not fn:
                return self._enviar(404, '{"erro":"rota inexistente"}', "application/json", cache=False)
            extra = [self._renovar(s)] if self.headers.get("X-Atividade") else []  # so acao do usuario estende a sessao
            try:
                codigo, corpo, tipo, cab = fn(q, JANELAS.get((q.get("janela") or ["24h"])[0], 24))
                return self._enviar(codigo, corpo, tipo, extra=extra + cab, cache=False)
            except Exception as e:  # LAPI fora, credencial errada, arquivo ilegivel...
                self._log("erro em %s: %s" % (caminho, e))
                return self._enviar(502, json.dumps({"erro": "Não foi possível consultar o CrowdSec para esta seção."}),
                                    "application/json; charset=utf-8", extra=extra, cache=False)

        def do_POST(self):
            p, caminho = self._rota()
            # Le o corpo ANTES de qualquer resposta: fechar a conexao com o corpo pendente pode gerar um RST e o
            # navegador veria "falha de conexao" em vez do 401/403 de verdade.
            self._corpo = self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 4096))
            if not self._ip_ok():
                return self._negar_ip()
            if not self._origem_ok():
                return self._enviar(403, "origem inválida", "text/plain; charset=utf-8", cache=False)
            if caminho == "/api/liberar":
                return self._liberar()
            form = parse_qs(self._corpo.decode("utf-8", "replace"))
            if caminho == "/logout":
                self._log("logout")
                return self._redir("/login", [self._cookie("", apagar=True)])
            if caminho != "/login":
                return self._enviar(404, "não encontrado", "text/plain; charset=utf-8", cache=False)
            usuario = (form.get("usuario") or [""])[0].strip()
            senha = (form.get("senha") or [""])[0]
            lembrar = bool(cfg.lembrar_dias) and (form.get("lembrar") or [""])[0] == "1"
            ip, chave_u = self._ip(), "u:" + usuario.lower()
            if sv.lim.bloqueado("i:" + ip, chave_u):
                self._log("login bloqueado (muitas tentativas) uid=%s" % usuario[:64])
                return self._login_pag("Muitas tentativas. Aguarde alguns minutos.", 429)
            try:
                if cfg.demo:
                    ok, nome, grupos = (usuario == "demo" and senha == "demo"), "Usuário Demonstração", ()
                else:
                    ok, nome, grupos = autenticar(cfg, usuario, senha, ip, self._log)
            except LdapIndisponivel as e:
                self._log("ldap indisponivel: %s" % e)
                return self._login_pag("Servidor de autenticação indisponível. Tente novamente.", 503)
            por_grupo = bool(cfg.allowed_group) and cfg.allowed_group in grupos
            if ok and not cfg.demo and usuario.lower() not in cfg.allowed and not por_grupo:
                self._log("login negado (sem permissao) uid=%s" % usuario)
                sv.lim.falha("i:" + ip, chave_u)
                return self._login_pag("Seu usuário não tem permissão para este painel.", 403)
            if not ok:
                self._log("login falhou uid=%s" % usuario[:64])
                sv.lim.falha("i:" + ip, chave_u)
                time.sleep(0.7)
                return self._login_pag("Usuário ou senha inválidos.", 401)
            sv.lim.ok("i:" + ip, chave_u)
            agora = int(time.time())
            self._log("login ok uid=%s%s%s" % (usuario, " (grupo)" if por_grupo else "", " (lembrar de mim)" if lembrar else ""))
            self._redir("/", [self._cookie(criar_token(cfg.secret, usuario, nome, agora, agora, lembrar),
                                           max_age=cfg.lembrar_max if lembrar else None)])

    return H


def gerar_hash_interativo():
    """python3 painel.py --gerar-hash : pede a senha duas vezes (sem eco) e imprime a linha UNBAN_HASH=... para o .env."""
    import getpass
    a = getpass.getpass("Nova senha de liberacao (minimo 10 caracteres): ")
    if len(a) < 10:
        sys.exit("Senha curta demais (minimo 10 caracteres).")
    if getpass.getpass("Repita a senha: ") != a:
        sys.exit("As senhas nao conferem.")
    print("UNBAN_HASH=%s" % gerar_hash_senha(a))


def main():
    if "--gerar-hash" in sys.argv:
        return gerar_hash_interativo()
    cfg = Config()
    if cfg.demo and cfg.bind not in ("127.0.0.1", "localhost"):
        sys.exit("PAINEL_DEMO=1 so e permitido com PAINEL_BIND=127.0.0.1")
    if len(cfg.secret) < 32:
        sys.exit("PAINEL_SECRET ausente ou curto (minimo 32 caracteres)")
    if not cfg.demo and (not (cfg.allowed or cfg.allowed_group) or not cfg.lapi_password):
        sys.exit("Defina ALLOWED_GROUP (ou ALLOWED_USERS) e LAPI_PASSWORD no .env")
    if not cfg.demo:
        for b in cfg.brokers:
            falta = [n for n, v in (("host", b["host"]), ("LDAP_BASE", cfg.ldap_base), ("CA (LDAP_CA)", b["ca"]), ("nome do certificado (LDAP_NAME)", b["name"])) if not v]
            if falta:
                sys.exit("LDAP incompleto no .env (servidor %s): falta %s. Veja a secao Autenticacao do README." % (b["nome"], ", ".join(falta)))
            if not os.path.isfile(b["ca"]):
                sys.exit("Certificado do LDAP nao encontrado: %s (veja README, 'Obter o certificado do LDAP')" % b["ca"])
    sv = Servico(cfg)
    if not cfg.demo:
        threading.Thread(target=amostrar, args=(sv,), daemon=True).start()
    srv = ThreadingHTTPServer((cfg.bind, cfg.port), criar_handler(sv))
    print("painel em http://%s:%d (demo=%s, usuarios=%d)" % (cfg.bind, cfg.port, cfg.demo, len(cfg.allowed)), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
