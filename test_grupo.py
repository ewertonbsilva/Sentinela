"""Acesso por grupo do LDAP (ALLOWED_GROUP): o painel é aberto a quem tem o grupo no memberOf. python -m unittest test_grupo"""
import os
import tempfile
import unittest
import urllib.error
import urllib.parse
import urllib.request
from unittest import mock

import painel
from test_liberar import SEGREDO, LapiFalsa, servidor

GRUPO = "cn=sentinela,ou=groups,dc=exemplo,dc=com"


class SemRedirecionar(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class AcessoPorGrupo(unittest.TestCase):
    def setUp(self):
        self.lapi = servidor(LapiFalsa)
        self.estado = tempfile.TemporaryDirectory()
        env = {"PAINEL_SECRET": SEGREDO, "LAPI_URL": "http://127.0.0.1:%d" % self.lapi.server_address[1], "LAPI_PASSWORD": "x",
               "ALLOWED_USERS": "", "ALLOWED_GROUP": GRUPO.upper(), "UNBAN_USERS": "", "UNBAN_HASH": "",
               "PAINEL_ESTADO": self.estado.name, "PAINEL_DEMO": "", "ALLOWED_IPS": "", "PAINEL_BASE": ""}
        with mock.patch.dict(os.environ, env):
            self.cfg = painel.Config()
        self.web = servidor(painel.criar_handler(painel.Servico(self.cfg)))
        self.base = "http://127.0.0.1:%d" % self.web.server_address[1]

    def tearDown(self):
        self.web.shutdown()
        self.lapi.shutdown()
        self.estado.cleanup()

    def entrar(self, usuario, grupos):
        corpo = urllib.parse.urlencode({"usuario": usuario, "senha": "x"}).encode()
        r = urllib.request.Request(self.base + "/login", data=corpo, headers={"Origin": self.base}, method="POST")
        with mock.patch.object(painel, "autenticar", return_value=(True, usuario.title(), tuple(g.lower() for g in grupos))):
            try:
                resp = urllib.request.build_opener(SemRedirecionar).open(r, timeout=10)
                return resp.status, resp.headers.get("Set-Cookie", "")
            except urllib.error.HTTPError as e:
                try:
                    return e.code, e.headers.get("Set-Cookie", "")
                finally:
                    e.close()

    def test_membro_do_grupo_entra_mesmo_sem_estar_na_lista(self):
        self.assertEqual(self.cfg.allowed, set())  # nenhuma lista de usuarios
        codigo, cookie = self.entrar("carlos", [GRUPO, "cn=outro,ou=groups,dc=exemplo,dc=com"])
        self.assertIn(codigo, (302, 303))
        self.assertIn("sentinela_sessao=", cookie)

    def test_quem_nao_esta_no_grupo_e_recusado(self):
        codigo, cookie = self.entrar("diana", ["cn=rh,ou=groups,dc=exemplo,dc=com"])
        self.assertEqual(codigo, 403)
        self.assertNotIn("sentinela_sessao=", cookie)

    def test_sem_nenhum_grupo_e_recusado(self):
        self.assertEqual(self.entrar("eva", [])[0], 403)

    def test_grupo_parecido_nao_vale(self):
        self.assertEqual(self.entrar("fabio", ["cn=sentinela2,ou=groups,dc=exemplo,dc=com"])[0], 403)


if __name__ == "__main__":
    unittest.main()
