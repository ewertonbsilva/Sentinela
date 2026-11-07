"""Testes do modulo de dados com amostras de exemplo (tests_data/): python -m unittest test_dados"""
import os
import unittest
from datetime import datetime, timezone

import dados

AQUI = os.path.dirname(os.path.abspath(__file__))
METRICAS = os.path.join(AQUI, "tests_data", "metricas_exemplo.txt")
ETC = os.path.join(AQUI, "tests_data", "etc-crowdsec")


def metricas():
    with open(METRICAS, encoding="utf-8") as f:
        return dados.parse_prom(f.read())


class Prometheus(unittest.TestCase):
    def test_parse_amostra_real(self):
        am = metricas()
        self.assertGreater(len(am), 300)
        info = [r for n, r, v in am if n == "cs_info"]
        self.assertTrue(info and info[0]["version"].startswith("v1."))

    def test_parse_casos_de_borda(self):
        am = dados.parse_prom('# HELP x\nx{a="b\\"c",d="e"} 3 1700000000\ny 1.5e+09\nz{a="1"} NaN\nlixo sem valor\n')
        self.assertEqual(am[0], ("x", {"a": 'b"c', "d": "e"}, 3.0))
        self.assertEqual(am[1][2], 1.5e9)
        self.assertEqual(len(am), 3)  # NaN e valido como float; 'lixo' nao

    def test_saude_com_dados_reais(self):
        s = dados.saude(metricas(), agora=1.7931516e9)
        self.assertTrue(s["versao"].startswith("v1."))
        self.assertTrue(s["recursos"].get("lapi"))
        self.assertTrue(s["fontes"])
        for f in s["fontes"]:
            self.assertGreaterEqual(f["lidas"], 0)
            self.assertTrue(f["pct_ok"] is None or 0 <= f["pct_ok"] <= 100)
        nomes = {c["nome"] for c in s["cenarios"]}
        self.assertIn("local/http-404-flood", nomes)
        flood = next(c for c in s["cenarios"] if c["nome"] == "local/http-404-flood")
        self.assertGreaterEqual(flood["overflow"], 1)
        self.assertTrue(any(d["motivo"] == "local/http-404-flood" and d["acao"] == "ban" for d in s["decisoes"]))
        self.assertIsNotNone(s["capi"]["quando"])
        self.assertIsNone(s["papi"])  # PAPI = 0: host sem inscricao no Console
        self.assertTrue(s["lapi_rotas"] and s["lapi_bouncers"])
        self.assertTrue(any(w["motivo"] == "rede interna" for w in s["whitelists"]))

    def test_saude_vazia_nao_quebra(self):
        s = dados.saude([])
        self.assertEqual((s["versao"], s["fontes"], s["capi"]), ("", [], None))


class Recente(unittest.TestCase):
    def test_snapshot_com_dados_reais(self):
        s = dados.snapshot_fontes(metricas())
        glpi = next(v for k, v in s.items() if k.endswith("proxy-host-24_access.log"))
        self.assertGreaterEqual(glpi[0], glpi[1] + glpi[2] - 1)  # lidas >= ok + ko (a menos de linha em transito)
        self.assertEqual(glpi[2], 266)  # o residuo do inicio do CrowdSec

    def test_residuo_antigo_nao_aparece_no_recente(self):
        antigo = {"a": (2315, 2049, 266)}
        novo = {"a": (2447, 2181, 266)}  # 132 linhas novas, todas interpretadas; as 266 falhas ja existiam
        r = dados.delta_fontes(antigo, novo)["a"]
        self.assertEqual((r["lidas"], r["ok"], r["ko"], r["pct_ok"]), (132, 132, 0, 100.0))

    def test_falha_nova_aparece(self):
        r = dados.delta_fontes({"a": (100, 90, 10)}, {"a": (200, 170, 30)})["a"]
        self.assertEqual((r["ok"], r["ko"], r["pct_ok"]), (80, 20, 80.0))

    def test_reinicio_do_crowdsec_nao_gera_negativo(self):
        r = dados.delta_fontes({"a": (5000, 4900, 100)}, {"a": (40, 40, 0)})["a"]  # contadores zeraram
        self.assertEqual((r["lidas"], r["ok"], r["ko"], r["pct_ok"]), (40, 40, 0, 100.0))

    def test_sem_linhas_no_periodo_e_fonte_nova(self):
        self.assertIsNone(dados.delta_fontes({"a": (10, 10, 0)}, {"a": (10, 10, 0)})["a"]["pct_ok"])
        self.assertEqual(dados.delta_fontes({}, {"b": (7, 6, 1)})["b"]["lidas"], 7)


class OQueTentou(unittest.TestCase):
    EV = [{"metodo": "GET", "caminho": "/wp-login.php", "status": "404", "host": "a.exemplo.com", "ua": "curl/8"}] * 3 + \
         [{"metodo": "GET", "caminho": "/.env", "status": "403", "host": "a.exemplo.com", "ua": "curl/8"},
          {"metodo": "POST", "caminho": "/xmlrpc.php", "status": "404", "host": "b.exemplo.com", "ua": "-"}]

    def test_resumo_agrupa_e_ordena(self):
        r = dados.resumo_eventos(self.EV)
        self.assertEqual(r["top"][0], {"req": "GET /wp-login.php", "status": "404", "n": 3})
        self.assertEqual(len(r["top"]), 3)
        self.assertEqual(r["agentes"], [("curl/8", 4)])  # "-" nao e programa
        self.assertEqual(r["hosts"][0], ("a.exemplo.com", 4))
        self.assertEqual(r["distintos"], 3)

    def test_resumo_vazio(self):
        r = dados.resumo_eventos([])
        self.assertEqual((r["top"], r["agentes"], r["hosts"]), ([], [], []))

    def test_detalhar_inclui_o_resumo(self):
        a = {"id": 1, "events": [{"timestamp": "2026-10-28T10:00:00Z", "meta": [
            {"key": "http_verb", "value": "GET"}, {"key": "http_path", "value": "/.git/config"}, {"key": "http_status", "value": "404"}]}]}
        self.assertEqual(dados.detalhar(a)["resumo"]["top"][0]["req"], "GET /.git/config")


class Glossario(unittest.TestCase):
    """Todo cenario instalado no host precisa ter explicacao em portugues no balao (lista real em tests_data/)."""

    @classmethod
    def setUpClass(cls):
        import json
        import shutil
        import subprocess
        node = shutil.which("node")
        if not node:
            raise unittest.SkipTest("node nao encontrado")
        js = os.path.join(AQUI, "static", "glossario.js")
        r = subprocess.run([node, "-e", "global.window={};require(process.argv[1]);console.log(JSON.stringify(window.GLOSSARIO))", js],
                           capture_output=True, text=True, encoding="utf-8", timeout=20)
        cls.g = json.loads(r.stdout)

    def test_todos_os_instalados_tem_explicacao(self):
        with open(os.path.join(AQUI, "tests_data", "cenarios_instalados.txt"), encoding="utf-8") as f:
            nomes = [l.strip() for l in f if l.strip()]
        self.assertGreaterEqual(len(nomes), 50)
        faltam = [n for n in nomes if n not in self.g["cenarios"]]
        self.assertEqual(faltam, [], "sem explicacao no glossario.js: %s" % faltam)

    def test_entradas_completas(self):
        for nome, c in self.g["cenarios"].items():
            self.assertTrue(c.get("t") and len(c.get("d", "")) > 30, nome)
            self.assertIn(c.get("k"), ("balde", "gatilho", "condicional"), nome)
            if c["k"] == "balde" and "cap" in c:
                self.assertTrue(c.get("leak"), nome)

    def test_acoes_e_origens_usadas_pelo_painel(self):
        self.assertIn("ban", self.g["acoes"])
        for o in ("crowdsec", "cscli", "CAPI"):
            self.assertIn(o, self.g["origens"])

    def test_cenario_proprio_e_o_exemplo_do_usuario(self):
        self.assertIn("Varredura", self.g["cenarios"]["crowdsecurity/http-probing"]["d"])


class Configuracao(unittest.TestCase):
    def test_meta_yaml_do_cenario_real(self):
        with open(os.path.join(ETC, "scenarios", "local-http-404-flood.yaml"), encoding="utf-8") as f:
            m = dados.meta_yaml(f.read())
        self.assertEqual((m["name"], m["type"], m["capacity"], m["leakspeed"], m["blackhole"]),
                         ("local/http-404-flood", "leaky", "20", "10s", "1m"))
        self.assertIn("404", m["description"])

    def test_meta_yaml_bloco(self):
        self.assertEqual(dados.meta_yaml("name: a/b\ndescription: >-\n  texto longo\n")["description"], "texto longo")

    def test_ler_config_exemplo(self):
        c = dados.ler_config(ETC)
        self.assertEqual(c["acquisicao"][0]["arquivo"], "acquis.d/npm.yaml")
        self.assertIn("nginx-proxy-manager", c["acquisicao"][0]["conteudo"])
        cen = {x["nome"]: x for x in c["cenarios"]}
        self.assertEqual(cen["local/http-404-flood"]["origem"], "local")
        self.assertTrue(cen["local/http-404-flood"]["legivel"])
        self.assertEqual({s["estagio"] for s in c["parsers"]}, {"s01-parse", "s02-enrich"})

    def test_pasta_inexistente_nao_quebra(self):
        c = dados.ler_config(os.path.join(ETC, "nao-existe"))
        self.assertEqual((c["acquisicao"], c["cenarios"], c["parsers"]), ([], [], []))

    def test_nome_do_hub_pelo_link(self):
        self.assertEqual(dados._nome_hub("/etc/crowdsec/hub/scenarios/crowdsecurity/CVE-2022-26134.yaml"),
                         "crowdsecurity/CVE-2022-26134")
        self.assertIsNone(dados._nome_hub("/outro/lugar.yaml"))


def alerta(i, ip, cen, ev, iso, pais="US", dec=None):
    return {"id": i, "scenario": cen, "events_count": ev, "start_at": iso, "created_at": iso,
            "source": {"ip": ip, "cn": pais, "as_name": "AS1 X"}, "decisions": [dec] if dec else []}


class Alertas(unittest.TestCase):
    A = [alerta(1, "1.1.1.1", "a/x", 10, "2026-10-28T10:00:00Z", dec={"type": "ban", "origin": "crowdsec", "duration": "2h0m0s"}),
         alerta(2, "1.1.1.1", "b/y", 5, "2026-10-28T11:00:00Z", "BR"),
         alerta(3, "2.2.2.2", "a/x", 7, "2026-10-27T09:00:00Z")]

    def test_compactar_ordena_pelo_mais_novo(self):
        c = dados.compactar_alertas(self.A)
        self.assertEqual([x["id"] for x in c], [2, 1, 3])
        self.assertEqual(c[1]["expira"], "2h 00m")
        self.assertEqual(c[1]["origem"], "crowdsec")
        self.assertEqual(c[0]["expira"], "")

    def test_por_cenario(self):
        r = {x["nome"]: x for x in dados.por_cenario(self.A)}
        self.assertEqual((r["a/x"]["alertas"], r["a/x"]["ips"], r["a/x"]["eventos"]), (2, 2, 17))
        self.assertEqual(dados.por_cenario(self.A)[0]["nome"], "a/x")

    def test_consulta_ip(self):
        r = dados.consulta_ip("1.1.1.1", self.A[:2], [{"type": "ban", "origin": "CAPI", "duration": "3h0m0s", "scope": "Ip", "value": "1.1.1.1"},
                                                    {"type": "ban", "duration": "-1m"}])
        self.assertEqual((r["total_alertas"], r["total_eventos"]), (2, 15))
        self.assertEqual(len(r["decisoes"]), 1)  # a expirada nao conta
        self.assertEqual(r["decisoes"][0]["origem"], "CAPI")
        self.assertEqual(r["cenarios"][0][1], 1)

    def test_mesclar_cenarios(self):
        r = dados.mesclar_cenarios([{"nome": "a/x", "alertas": 3, "ips": 1, "eventos": 9, "ultimo": "", "pais_top": "US"}],
                                   [{"nome": "a/x", "origem": "hub", "descricao": "d", "legivel": True},
                                    {"nome": "c/z", "origem": "hub", "descricao": None, "legivel": False}],
                                   [{"nome": "a/x", "instanciados": 5, "overflow": 2}])
        self.assertEqual([x["nome"] for x in r], ["a/x", "c/z"])
        self.assertEqual((r[0]["instalado"], r[0]["overflow"], r[0]["descricao"]), (True, 2, "d"))
        self.assertEqual((r[1]["alertas"], r[1]["overflow"]), (0, 0))

    def test_csv(self):
        t = dados.csv_texto(["a", "b"], [["=1+1", "x;y"], ["ok", None]])
        self.assertTrue(t.startswith("﻿a;b\r\n"))
        self.assertIn("'=1+1", t)       # sem formula ativa
        self.assertIn('"x;y"', t)       # separador dentro do campo fica entre aspas
        self.assertTrue(t.endswith("ok;\r\n"))

    def test_ip_valido(self):
        self.assertEqual(dados.ip_valido(" 1.2.3.4 "), "1.2.3.4")
        self.assertEqual(dados.ip_valido("2001:db8::1"), "2001:db8::1")
        for ruim in ("", "1.2.3", "a.b.c.d", "1.2.3.4/24", "1.2.3.4; rm", None):
            self.assertIsNone(dados.ip_valido(ruim), ruim)

    def test_mapa_de_calor_e_top_as(self):
        r = dados.resumir(self.A, [], 168, agora=datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc))
        self.assertEqual(sum(sum(l) for l in r["mapa"]), 3)
        self.assertEqual(r["top_as"][0], ("AS1 X", 3))
        self.assertEqual(len(r["mapa"]), 7)


if __name__ == "__main__":
    unittest.main()
