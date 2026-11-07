"""Liberar IP: sobe o servidor do painel de verdade contra uma LAPI falsa. python -m unittest test_liberar"""
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import painel

SENHA = "senha-de-teste-123"
SEGREDO = "s" * 40


class LapiFalsa(BaseHTTPRequestHandler):
    chamadas = []  # (metodo, caminho, autorizacao)

    def log_message(self, *a):
        pass

    def _resp(self, obj, codigo=200):
        corpo = json.dumps(obj).encode()
        self.send_response(codigo)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        LapiFalsa.chamadas.append(("POST", self.path, ""))
        self._resp({"code": 200, "token": "tok1", "expire": "2099-01-01T00:00:00Z"})

    def do_GET(self):
        LapiFalsa.chamadas.append(("GET", self.path, self.headers.get("Authorization", "")))
        self._resp([])

    def do_DELETE(self):
        LapiFalsa.chamadas.append(("DELETE", self.path, self.headers.get("Authorization", "")))
        self._resp({"nbDeleted": "2"})


def servidor(handler, **extra):
    s = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


class Base(unittest.TestCase):
    unban_hash = None  # None = usa o hash de SENHA

    def setUp(self):
        LapiFalsa.chamadas = []
        self.lapi = servidor(LapiFalsa)
        self.estado = tempfile.TemporaryDirectory()
        h = painel.gerar_hash_senha(SENHA, 20000) if self.unban_hash is None else self.unban_hash
        env = {"PAINEL_SECRET": SEGREDO, "LAPI_URL": "http://127.0.0.1:%d" % self.lapi.server_address[1], "LAPI_PASSWORD": "x",
               "ALLOWED_USERS": "ana", "UNBAN_USERS": "bia", "UNBAN_HASH": h, "PAINEL_ESTADO": self.estado.name,
               "PAINEL_DEMO": "", "ALLOWED_IPS": "", "PAINEL_BASE": ""}
        with mock.patch.dict(os.environ, env):
            self.cfg = painel.Config()
        self.sv = painel.Servico(self.cfg)
        self.web = servidor(painel.criar_handler(self.sv))
        self.base = "http://127.0.0.1:%d" % self.web.server_address[1]

    def tearDown(self):
        self.web.shutdown()
        self.lapi.shutdown()
        self.estado.cleanup()

    def cookie(self, uid):
        agora = int(time.time())
        return "sentinela_sessao=" + painel.criar_token(SEGREDO.encode(), uid, uid.title(), agora, agora)

    def post(self, corpo, uid="bia", origem=True):
        h = {"Content-Type": "application/json"}
        if uid:
            h["Cookie"] = self.cookie(uid)
        if origem:  # True = o proprio painel; ou o texto de uma origem forjada
            h["Origin"] = self.base if origem is True else origem
        r = urllib.request.Request(self.base + "/api/liberar", data=json.dumps(corpo).encode(), headers=h, method="POST")
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                bruto = e.read() or b"{}"
                try:
                    return e.code, json.loads(bruto)
                except ValueError:  # 403 de origem invalida responde texto puro
                    return e.code, {"texto": bruto.decode("utf-8", "replace")}
            finally:
                e.close()

    def get(self, caminho, uid="bia"):
        r = urllib.request.Request(self.base + caminho, headers={"Cookie": self.cookie(uid)})
        with urllib.request.urlopen(r, timeout=10) as resp:
            return json.loads(resp.read())

    def deletes(self):
        return [c for c in LapiFalsa.chamadas if c[0] == "DELETE"]


class Senha(unittest.TestCase):
    def test_ida_e_volta_e_sal_diferente(self):
        a, b = painel.gerar_hash_senha(SENHA, 20000), painel.gerar_hash_senha(SENHA, 20000)
        self.assertNotEqual(a, b)  # sal aleatorio
        self.assertTrue(painel.verificar_senha(SENHA, a))
        self.assertFalse(painel.verificar_senha(SENHA + "x", a))
        self.assertNotIn(SENHA, a)

    def test_hash_ruim_nunca_valida(self):
        for ruim in ("", None, "lixo", "md5:1:a:b", "pbkdf2_sha256:5:aa:bb", "pbkdf2_sha256:abc:aa:bb", "pbkdf2_sha256:20000:::"):
            self.assertFalse(painel.verificar_senha(SENHA, ruim), ruim)

    def test_senha_vazia_nao_valida(self):
        self.assertFalse(painel.verificar_senha("", painel.gerar_hash_senha(SENHA, 20000)))


class Liberar(Base):
    def test_sem_sessao_401(self):
        self.assertEqual(self.post({"ip": "203.0.113.9"}, uid=None)[0], 401)
        self.assertEqual(self.deletes(), [])

    def test_origem_de_outro_site_403(self):
        """CSRF: um site de fora fazendo o navegador do usuario (com o cookie) disparar a liberacao."""
        corpo = {"ip": "203.0.113.9", "motivo": "teste valido", "senha": SENHA}
        self.assertEqual(self.post(corpo, origem="http://site-malicioso.example")[0], 403)
        self.assertEqual(self.deletes(), [])

    def test_quem_so_entra_no_painel_nao_libera(self):
        st, d = self.post({"ip": "203.0.113.9", "motivo": "teste valido", "senha": SENHA}, uid="ana")
        self.assertEqual(st, 403)
        self.assertIn("permissão", d["erro"])
        self.assertEqual(self.deletes(), [])

    def test_validacoes(self):
        for corpo in ({"ip": "1.2.3.0/24", "motivo": "faixa inteira", "senha": SENHA}, {"ip": "lixo", "motivo": "ip ruim", "senha": SENHA},
                      {"ip": "203.0.113.9", "motivo": "ab", "senha": SENHA}, {"ip": "203.0.113.9", "motivo": "x" * 201, "senha": SENHA}, {}):
            self.assertEqual(self.post(corpo)[0], 400, corpo)
        self.assertEqual(self.deletes(), [])

    def test_senha_errada_e_travamento_na_4a(self):
        ruim = {"ip": "203.0.113.9", "motivo": "teste valido", "senha": "errada"}
        self.assertEqual([self.post(ruim)[0] for _ in range(3)], [403, 403, 403])
        st, d = self.post(dict(ruim, senha=SENHA))  # mesmo com a senha certa, a 4a tentativa esta travada
        self.assertEqual(st, 429)
        self.assertEqual(self.deletes(), [])
        self.assertEqual([i["resultado"] for i in self.sv.aud.lista()], ["senha incorreta"] * 3)

    def test_sucesso_remove_registra_e_aparece_no_historico(self):
        st, d = self.post({"ip": " 203.0.113.9 ", "motivo": "Setor de marketing bloqueado por engano", "senha": SENHA})
        self.assertEqual((st, d["removidos"], d["ip"]), (200, 2, "203.0.113.9"))
        dl = self.deletes()
        self.assertEqual(len(dl), 1)
        self.assertEqual(dl[0][1], "/v1/decisions?ip=203.0.113.9")
        self.assertEqual(dl[0][2], "Bearer tok1")
        item = self.sv.aud.lista()[0]
        self.assertEqual((item["usuario"], item["alvo"], item["removidos"], item["resultado"]), ("bia", "203.0.113.9", 2, "liberado"))
        self.assertIn("marketing", item["motivo"])
        with open(os.path.join(self.estado.name, "liberacoes.jsonl"), encoding="utf-8") as f:  # persistido em disco
            self.assertEqual(json.loads(f.readline())["alvo"], "203.0.113.9")
        hist = self.get("/api/liberacoes")
        self.assertTrue(hist["pode"] and hist["ativo"])
        self.assertEqual(hist["itens"][0]["usuario"], "bia")

    def test_historico_sobrevive_a_reinicio(self):
        self.post({"ip": "203.0.113.9", "motivo": "teste de persistencia", "senha": SENHA})
        outro = painel.Auditoria(self.estado.name)
        self.assertEqual(outro.lista()[0]["alvo"], "203.0.113.9")

    def test_ipv6_valido(self):
        self.assertEqual(self.post({"ip": "2001:db8::1", "motivo": "teste ipv6 valido", "senha": SENHA})[0], 200)
        self.assertEqual(self.deletes()[0][1], "/v1/decisions?ip=2001:db8::1")

    def test_flag_pode_liberar_na_lista_de_bloqueios(self):
        self.assertTrue(self.get("/api/bloqueios", uid="bia")["pode_liberar"])
        self.assertFalse(self.get("/api/bloqueios", uid="ana")["pode_liberar"])

    def test_quem_libera_tambem_entra_no_painel(self):
        self.assertIn("bia", self.cfg.allowed)
        self.assertIn("ana", self.cfg.allowed)


class SemSenhaDefinida(Base):
    unban_hash = ""

    def test_funcao_desativada(self):
        st, d = self.post({"ip": "203.0.113.9", "motivo": "teste valido", "senha": SENHA})
        self.assertEqual(st, 403)
        self.assertIn("não está ativada", d["erro"])
        self.assertFalse(self.get("/api/bloqueios")["pode_liberar"])
        self.assertEqual(self.deletes(), [])


class RenovaTokenDaLapi(unittest.TestCase):
    def test_401_na_lapi_faz_novo_login_e_repete(self):
        class Lapi401(LapiFalsa):
            ja = False

            def do_DELETE(self):
                LapiFalsa.chamadas.append(("DELETE", self.path, self.headers.get("Authorization", "")))
                if not Lapi401.ja:
                    Lapi401.ja = True
                    return self._resp({"message": "expired"}, 401)
                self._resp({"nbDeleted": "1"})

        LapiFalsa.chamadas = []
        srv = servidor(Lapi401)
        try:
            with mock.patch.dict(os.environ, {"LAPI_URL": "http://127.0.0.1:%d" % srv.server_address[1], "LAPI_PASSWORD": "x", "PAINEL_SECRET": SEGREDO}):
                lapi = painel.Lapi(painel.Config())
            self.assertEqual(lapi.liberar("203.0.113.9"), 1)
            self.assertEqual(len([c for c in LapiFalsa.chamadas if c[0] == "POST"]), 2)  # login inicial + relogin
        finally:
            srv.shutdown()


if __name__ == "__main__":
    unittest.main()
