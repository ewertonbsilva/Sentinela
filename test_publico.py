"""Configuração neutra do repositório público: marca, fuso e molde do DN. python -m unittest test_publico"""
import os
import re
import unittest
import urllib.request
from unittest import mock

import dados
import painel
from test_liberar import SEGREDO, LapiFalsa, servidor


def config(**env):
    base = {"PAINEL_SECRET": SEGREDO, "LAPI_PASSWORD": "x", "ALLOWED_GROUP": "cn=a,dc=b", "PAINEL_DEMO": "", "PAINEL_BASE": ""}
    base.update(env)
    with mock.patch.dict(os.environ, base, clear=True):
        return painel.Config()


class Marca(unittest.TestCase):
    def test_sem_org_o_titulo_e_so_sentinela(self):
        self.assertEqual(config().titulo, "Sentinela")

    def test_org_entra_no_titulo(self):
        self.assertEqual(config(ORG_NOME="Empresa Exemplo").titulo, "Empresa Exemplo · Sentinela")

    def test_paginas_trazem_titulo_e_fuso_e_nada_do_orgao(self):
        lapi = servidor(LapiFalsa)
        env = {"PAINEL_SECRET": SEGREDO, "LAPI_URL": "http://127.0.0.1:%d" % lapi.server_address[1], "LAPI_PASSWORD": "x",
               "ALLOWED_GROUP": "cn=a,dc=b", "ORG_NOME": "Empresa <Exemplo>", "PAINEL_BASE": ""}
        with mock.patch.dict(os.environ, env):
            cfg = painel.Config()
        web = servidor(painel.criar_handler(painel.Servico(cfg)))
        try:
            html = urllib.request.urlopen("http://127.0.0.1:%d/login" % web.server_address[1], timeout=10).read().decode()
        finally:
            web.shutdown()
            lapi.shutdown()
        self.assertIn("Empresa &lt;Exemplo&gt; · Sentinela", html)  # escapado
        self.assertNotIn("Empresa <Exemplo>", html)
        self.assertNotRegex(html.lower(), r"cbmac|bombeiro|brasao")


class Ldap(unittest.TestCase):
    def test_sem_ldap_configurado_nao_ha_padrao_do_orgao(self):
        c = config()
        self.assertEqual((c.ldap_host, c.ldap_base, c.ldap_ca, c.ldap_name), ("", "", "", ""))
        self.assertEqual(c.ldap_user_dn, "uid={usuario},{base}")

    def test_molde_do_dn_e_aplicado_no_bind(self):
        c = config(LDAP_HOST="ldap.exemplo.com", LDAP_BASE="ou=people,dc=exemplo,dc=com", LDAP_CA="/x.crt",
                   LDAP_NAME="ldap.exemplo.com", LDAP_USER_DN="{usuario}@exemplo.com")
        visto = {}

        class Falso:
            def __init__(self, *a, user=None, **k):
                visto["dn"] = user

            def bind(self):
                return False

        with mock.patch("ldap3.Connection", Falso), mock.patch("ldap3.Tls"), mock.patch("ldap3.Server"):
            r = painel._autenticar_em(c, c.brokers[0], "ana.silva", "senha")
        self.assertEqual(r, (False, None, ()))
        self.assertEqual(visto["dn"], "ana.silva@exemplo.com")


class Fuso(unittest.TestCase):
    def test_fuso_padrao_e_sao_paulo(self):
        self.assertEqual(dados.TZ_NOME, os.environ.get("PAINEL_TZ", "America/Sao_Paulo"))

    def test_horario_local(self):
        from datetime import datetime, timezone
        self.assertEqual(dados.fmt_local(datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc), "%H:%M"), "09:00")


if __name__ == "__main__":
    unittest.main()
