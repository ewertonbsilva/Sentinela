"""Testes do painel (sem rede, sem CrowdSec): python -m unittest -v test_painel"""
import unittest
from datetime import datetime, timedelta, timezone

import painel


def alerta(i, ip, cen, ev, t, pais="US", decisao=None):
    return {"id": i, "scenario": cen, "events_count": ev, "start_at": t.isoformat(), "created_at": t.isoformat(),
            "source": {"ip": ip, "cn": pais, "as_name": "AS1 X"},
            "decisions": [decisao] if decisao else []}


class Token(unittest.TestCase):
    S = b"x" * 40

    def test_ida_e_volta(self):
        t = painel.criar_token(self.S, "ana", "Ana", 1000, 1000)
        self.assertEqual(painel.ler_token(self.S, t, 900, 28800, agora=1100)["u"], "ana")

    def test_adulterado_ou_outro_segredo(self):
        t = painel.criar_token(self.S, "ana", "Ana", 1000, 1000)
        corpo, ass = t.split(".")
        self.assertIsNone(painel.ler_token(self.S, corpo + "." + "A" + ass[1:], 900, 28800, agora=1100))
        self.assertIsNone(painel.ler_token(b"y" * 40, t, 900, 28800, agora=1100))
        self.assertIsNone(painel.ler_token(self.S, "lixo", 900, 28800, agora=1100))

    def test_inatividade_e_vida_maxima(self):
        t = painel.criar_token(self.S, "ana", "Ana", 1000, 1000)
        self.assertIsNone(painel.ler_token(self.S, t, 900, 28800, agora=2001))
        t2 = painel.criar_token(self.S, "ana", "Ana", 1000, 29850)  # ativa agora, mas com 28.900 s de vida
        self.assertIsNone(painel.ler_token(self.S, t2, 900, 28800, agora=29900))
        self.assertIsNotNone(painel.ler_token(self.S, t2, 900, 28800, agora=29700))


class Limitador(unittest.TestCase):
    def test_bloqueia_na_quinta_e_libera_depois(self):
        lim = painel.Limitador(5, 300)
        for i in range(4):
            lim.falha("i:1", "u:a", agora=100 + i)
        self.assertFalse(lim.bloqueado("i:1", agora=110))
        lim.falha("i:1", agora=111)
        self.assertTrue(lim.bloqueado("i:1", agora=112))
        self.assertTrue(lim.bloqueado("i:2", "i:1", agora=112))
        self.assertFalse(lim.bloqueado("i:1", agora=500))

    def test_sucesso_zera(self):
        lim = painel.Limitador(2, 300)
        lim.falha("a", agora=1)
        lim.falha("a", agora=2)
        lim.ok("a")
        self.assertFalse(lim.bloqueado("a", agora=3))


class Autenticacao(unittest.TestCase):
    cfg = painel.Config()

    def test_senha_vazia_nunca_chega_ao_ldap(self):
        self.assertEqual(painel.autenticar(self.cfg, "ana", ""), (False, None, ()))

    def test_usuario_invalido_nao_chega_ao_ldap(self):
        for u in ["", "a,b", "ana)(uid=*", "ana\\", "a" * 65, "ana mais"]:
            self.assertEqual(painel.autenticar(self.cfg, u, "x"), (False, None, ()), u)

    def test_escape_de_dn(self):
        self.assertEqual(painel.escapar_rdn("a,b=c"), "a\\,b\\=c")


class LembrarDeMim(unittest.TestCase):
    S = b"x" * 40

    def test_token_lembrado_vale_mais(self):
        t = painel.criar_token(self.S, "ana", "Ana", 1000, 1000, lembrar=True)
        n = painel.criar_token(self.S, "ana", "Ana", 1000, 1000)
        dois_dias = 1000 + 172800
        self.assertEqual(painel.ler_token(self.S, t, 900, 28800, agora=dois_dias, idle_m=259200, max_m=604800)["u"], "ana")
        self.assertIsNone(painel.ler_token(self.S, n, 900, 28800, agora=dois_dias, idle_m=259200, max_m=604800))
        self.assertIsNone(painel.ler_token(self.S, t, 900, 28800, agora=1000 + 700000, idle_m=900000, max_m=604800))  # passou do maximo
        self.assertIsNone(painel.ler_token(self.S, t, 900, 28800, agora=dois_dias))  # sem limites m: vale o normal

    def test_fluxo_http_em_modo_demo(self):
        import http.client
        import os
        import threading
        from http.server import ThreadingHTTPServer
        os.environ.update({"PAINEL_DEMO": "1", "PAINEL_SECRET": "x" * 40, "COOKIE_SECURE": "0"})
        try:
            cfg = painel.Config()
        finally:
            for k in ("PAINEL_DEMO", "PAINEL_SECRET", "COOKIE_SECURE"):
                os.environ.pop(k)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), painel.criar_handler(painel.Servico(cfg)))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        porta = srv.server_address[1]
        try:
            def req(metodo, caminho, corpo=None, cab=None):
                c = http.client.HTTPConnection("127.0.0.1", porta, timeout=10)
                h = {"Host": "127.0.0.1:%d" % porta, "Origin": "http://127.0.0.1:%d" % porta}
                h.update(cab or {})
                if corpo is not None:
                    h["Content-Type"] = "application/x-www-form-urlencoded"
                c.request(metodo, caminho, body=corpo, headers=h)
                r = c.getresponse()
                return r, r.read()
            r, corpo = req("GET", "/login")
            self.assertIn(b'name="lembrar"', corpo)                      # a caixa aparece na tela
            r, _ = req("POST", "/login", "usuario=demo&senha=demo")
            self.assertEqual(r.status, 303)
            self.assertNotIn("Max-Age", r.getheader("Set-Cookie"))      # sem marcar: cookie de sessao
            r, _ = req("POST", "/login", "usuario=demo&senha=demo&lembrar=1")
            sc = r.getheader("Set-Cookie")
            self.assertIn("Max-Age=604800", sc)                          # marcado: persistente por 7 dias
            self.assertIn("HttpOnly", sc)
        finally:
            srv.shutdown()
            srv.server_close()


class BrokerPorRede(unittest.TestCase):
    def _cfg(self):
        import os
        os.environ.update({"BROKER_A_HOST": "a.test", "BROKER_A_REDES": "192.0.2.0/24",
                           "BROKER_B_HOST": "b.test", "BROKER_B_REDES": "198.51.100.0/24"})
        try:
            return painel.Config()
        finally:
            for k in ("BROKER_A_HOST", "BROKER_A_REDES", "BROKER_B_HOST", "BROKER_B_REDES"):
                os.environ.pop(k)

    def test_sem_broker_no_env_usa_o_ldap_unico(self):
        cfg = painel.Config()
        self.assertEqual(len(cfg.brokers), 1)
        self.assertEqual(cfg.brokers[0]["host"], cfg.ldap_host)

    def test_ordem_pela_rede_do_cliente(self):
        cfg = self._cfg()
        nomes = lambda ip: [b["host"] for b in painel.ordenar_brokers(cfg.brokers, ip)]
        self.assertEqual(nomes("192.0.2.45"), ["a.test", "b.test"])
        self.assertEqual(nomes("198.51.100.30"), ["b.test", "a.test"])   # rede do B: B primeiro, A de reserva
        self.assertEqual(nomes("203.0.113.5"), ["a.test", "b.test"])   # rede desconhecida: ordem configurada
        self.assertEqual(nomes("lixo"), ["a.test", "b.test"])

    def test_cai_para_o_outro_so_se_nao_responder(self):
        cfg = self._cfg()
        chamadas, fora = [], set()
        orig = painel._autenticar_em

        def falso(c, b, u, s):
            chamadas.append(b["host"])
            if b["host"] in fora:
                raise painel.LdapIndisponivel("fora")
            return ((True, "Nome", ("cn=x",)) if s == "ok" else (False, None, ()))
        painel._autenticar_em = falso
        try:
            self.assertEqual(painel.autenticar(cfg, "ana", "ok", "198.51.100.30"), (True, "Nome", ("cn=x",)))
            self.assertEqual(chamadas, ["b.test"])                       # foi direto ao broker da rede dele
            chamadas.clear(); fora.add("b.test")
            self.assertEqual(painel.autenticar(cfg, "ana", "ok", "198.51.100.30")[0], True)
            self.assertEqual(chamadas, ["b.test", "a.test"])            # B fora do ar: cai para o A
            chamadas.clear()
            self.assertEqual(painel.autenticar(cfg, "ana", "errada", "192.0.2.45"), (False, None, ()))
            self.assertEqual(chamadas, ["a.test"])                       # senha errada e definitiva
            fora.update({"a.test", "b.test"})
            with self.assertRaises(painel.LdapIndisponivel):
                painel.autenticar(cfg, "ana", "ok", "192.0.2.45")
        finally:
            painel._autenticar_em = orig


class Detalhe(unittest.TestCase):
    def test_eventos_do_alerta(self):
        a = {"id": 7, "scenario": "x/y", "events_count": 30, "start_at": "2026-10-28T10:00:00Z", "stop_at": "2026-10-28T10:00:30Z",
             "source": {"ip": "1.2.3.4", "cn": "US", "as_name": "AS1"},
             "events": [{"timestamp": "2026-10-28T10:00:01Z", "meta": [
                 {"key": "http_verb", "value": "GET"}, {"key": "http_path", "value": "/.env"},
                 {"key": "http_status", "value": "404"}, {"key": "user_agent", "value": "curl/8"},
                 {"key": "source_ip", "value": "1.2.3.4"}, {"key": "http_args_len", "value": "0"}]}],
             "decisions": [{"type": "ban", "duration": "3h59m0s", "origin": "crowdsec"}]}
        d = painel.detalhar(a)
        self.assertEqual((d["ip"], d["total"], d["mostrados"]), ("1.2.3.4", 30, 1))
        e = d["eventos"][0]
        self.assertEqual((e["metodo"], e["caminho"], e["status"], e["ua"]), ("GET", "/.env", "404", "curl/8"))
        self.assertEqual(e["quando"], "28/10 07:00:01")  # fuso padrao America/Sao_Paulo (UTC-3)
        self.assertEqual(e["outros"], "http_args_len=0")  # source_ip e ruido, nao entra
        self.assertEqual(d["decisoes"][0]["expira"], "3h 59m")

    def test_sem_eventos_e_valores_longos(self):
        self.assertEqual(painel.detalhar({"id": 1})["eventos"], [])
        a = {"events": [{"meta": [{"key": "http_path", "value": "A" * 1000}]}]}
        self.assertEqual(len(painel.detalhar(a)["eventos"][0]["caminho"]), 300)

    def test_ban_guarda_id_do_alerta(self):
        ativos = [{"id": 42, "source": {"ip": "1.1.1.1"},
                   "decisions": [{"type": "ban", "value": "1.1.1.1", "duration": "1h0m0s"}]}]
        self.assertEqual(painel.resumir([], ativos, 24)["bans"][0]["alerta"], 42)


class HistoricoAmostras(unittest.TestCase):
    def test_precisa_de_duas_amostras(self):
        h = painel.Historico()
        self.assertIsNone(h.recente())
        h.registrar({"a": (1, 1, 0)}, ts=1000)
        self.assertIsNone(h.recente())

    def test_compara_com_a_amostra_mais_antiga_dentro_da_janela(self):
        h = painel.Historico()
        h.registrar({"a": (100, 100, 0)}, ts=0)        # 2 h atras: fora da janela de 60 min
        h.registrar({"a": (150, 140, 10)}, ts=4000)    # ~55 min atras: base
        h.registrar({"a": (200, 190, 10)}, ts=7200)    # agora
        r = h.recente(60)
        self.assertEqual(r["minutos"], 53)
        self.assertEqual(r["fontes"]["a"]["lidas"], 50)
        self.assertEqual(r["fontes"]["a"]["pct_ok"], 100.0)

    def test_usa_a_mais_antiga_quando_ainda_nao_completou_a_janela(self):
        h = painel.Historico()
        h.registrar({"a": (0, 0, 0)}, ts=1000)
        h.registrar({"a": (60, 60, 0)}, ts=1600)
        self.assertEqual(h.recente(60)["minutos"], 10)

    def test_limite_de_memoria(self):
        h = painel.Historico(maximo=5)
        for i in range(20):
            h.registrar({"a": (i, i, 0)}, ts=i)
        self.assertEqual(len(h._a), 5)


class ListaDeIps(unittest.TestCase):
    redes = [__import__("ipaddress").ip_network(x, strict=False) for x in ("192.0.2.45", "198.51.100.0/24")]

    def test_sem_lista_libera_todos(self):
        self.assertTrue(painel.ip_permitido([], "8.8.8.8"))

    def test_com_lista(self):
        self.assertTrue(painel.ip_permitido(self.redes, "192.0.2.45"))
        self.assertTrue(painel.ip_permitido(self.redes, "198.51.100.200"))
        self.assertFalse(painel.ip_permitido(self.redes, "192.0.2.46"))
        self.assertFalse(painel.ip_permitido(self.redes, "177.1.1.1"))

    def test_ip_ilegivel_e_negado(self):
        self.assertFalse(painel.ip_permitido(self.redes, "lixo"))
        self.assertFalse(painel.ip_permitido(self.redes, ""))


class Prefixo(unittest.TestCase):
    def _base(self, valor):
        import os
        antigo = os.environ.get("PAINEL_BASE")
        os.environ["PAINEL_BASE"] = valor
        try:
            return painel.Config().base
        finally:
            if antigo is None:
                del os.environ["PAINEL_BASE"]
            else:
                os.environ["PAINEL_BASE"] = antigo

    def test_normaliza_prefixo(self):
        self.assertEqual(self._base("/defesa"), "/defesa")
        self.assertEqual(self._base("defesa/"), "/defesa")
        self.assertEqual(self._base("/a/b/"), "/a/b")
        self.assertEqual(self._base(""), "")
        self.assertEqual(self._base("/"), "")


class Formatos(unittest.TestCase):
    def test_duracao(self):
        f = painel.fmt_duracao
        self.assertEqual(f("3h59m55.123s"), "3h 59m")
        self.assertEqual(f("59m5s"), "59m 05s")
        self.assertEqual(f("12s"), "12s")
        self.assertEqual(f("49h1m0s"), "2d 1h")
        self.assertIsNone(f("-5m"))
        self.assertIsNone(f(""))

    def test_iso_com_nanosegundos_e_sem_fracao(self):
        d = painel.parse_iso("2026-10-28T00:34:22.123456789Z")
        self.assertEqual((d.hour, d.minute, d.tzinfo is not None), (0, 34, True))
        self.assertEqual(painel.parse_iso("2026-10-28T00:34:22+00:00").second, 22)
        self.assertIsNone(painel.parse_iso("quebrado"))


class Resumo(unittest.TestCase):
    agora = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)

    def test_contagens_e_serie(self):
        t = self.agora - timedelta(hours=2)
        al = [alerta(1, "1.1.1.1", "a/x", 10, t), alerta(2, "1.1.1.1", "a/x", 5, t, "BR"),
              alerta(3, "2.2.2.2", "b/y", 7, t - timedelta(hours=1))]
        al.append(dict(alerta(4, "9.9.9.9", "a/x", 99, t), simulated=True))
        r = painel.resumir(al, [], 24, agora=self.agora)
        self.assertEqual(r["kpis"], {"bans": 0, "alertas": 3, "ips": 2, "paises": 2, "eventos": 22})
        self.assertEqual(r["top_cenarios"][0], ("a/x", 2))
        self.assertEqual(len(r["serie"]), 24)
        self.assertEqual(sum(p["n"] for p in r["serie"]), 3)
        self.assertEqual(r["passo"], "hora")

    def test_30_dias_agrupa_por_dia(self):
        r = painel.resumir([], [], 720, agora=self.agora)
        self.assertEqual((len(r["serie"]), r["passo"]), (30, "dia"))

    def test_bans_ativos_ignoram_expirados_e_duplicados(self):
        d = lambda v, dur, **k: dict({"type": "ban", "value": v, "duration": dur, "origin": "crowdsec", "scenario": "s"}, **k)
        t = self.agora
        ativos = [alerta(1, "1.1.1.1", "a/x", 10, t, decisao=d("1.1.1.1", "3h59m55s")),
                  alerta(2, "1.1.1.1", "a/x", 10, t, decisao=d("1.1.1.1", "2h0m0s")),
                  alerta(3, "2.2.2.2", "a/x", 10, t, decisao=d("2.2.2.2", "-3m")),
                  alerta(4, "3.3.3.3", "a/x", 10, t, decisao=d("3.3.3.3", "10m0s", simulated=True))]
        r = painel.resumir([], ativos, 24, agora=self.agora)
        self.assertEqual([b["ip"] for b in r["bans"]], ["1.1.1.1"])
        self.assertEqual(r["bans"][0]["expira"], "3h 59m")

    def test_alerta_sem_campos_nao_quebra(self):
        r = painel.resumir([{}, {"source": None, "decisions": None}], [{}], 24, agora=self.agora)
        self.assertEqual(r["kpis"]["alertas"], 2)

    def test_demo_gera_dados_validos(self):
        al, at = painel.dados_demo(24)
        r = painel.resumir(al, at, 24)
        self.assertGreater(r["kpis"]["alertas"], 0)


if __name__ == "__main__":
    unittest.main()
