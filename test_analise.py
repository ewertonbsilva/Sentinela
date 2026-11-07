"""Testes das analises do resumo (comparativo, pico, funil, reincidentes, sites): python -m unittest test_analise"""
import unittest
from datetime import datetime, timedelta, timezone

import dados

AGORA = datetime(2026, 11, 6, 15, 0, tzinfo=timezone.utc)


def alerta(ip, minutos, cen="crowdsec/http-probing", host=None, ban=True, eventos=10):
    t = AGORA - timedelta(minutes=minutos)
    a = {"id": 1, "scenario": cen, "events_count": eventos, "start_at": t.isoformat(), "created_at": t.isoformat(),
         "source": {"ip": ip, "cn": "BR", "as_name": "AS1"}, "decisions": []}
    if ban:
        a["decisions"] = [{"type": "ban", "value": ip, "duration": "3h0m0s", "origin": "crowdsec"}]
    if host:
        a["events"] = [{"timestamp": t.isoformat(), "meta": [{"key": "target_fqdn", "value": host}]}]
    return a


class Comparativo(unittest.TestCase):
    def test_variacao(self):
        self.assertEqual(dados.variacao(150, 100), 50)
        self.assertEqual(dados.variacao(50, 100), -50)
        self.assertIsNone(dados.variacao(5, 0))

    def test_resumo_com_periodo_anterior(self):
        atuais = [alerta("1.1.1.1", 10), alerta("2.2.2.2", 20), alerta("2.2.2.2", 30)]
        ant = [alerta("3.3.3.3", 70)]
        r = dados.resumir(atuais, atuais, 1, AGORA, ant)
        self.assertEqual(r["comparativo"]["alertas"], {"atual": 3, "anterior": 1, "pct": 200})
        self.assertEqual(r["comparativo"]["ips"]["anterior"], 1)

    def test_sem_anterior_nao_inventa_comparativo(self):
        r = dados.resumir([alerta("1.1.1.1", 10)], [], 1, AGORA)
        self.assertIsNone(r["comparativo"])


class Reincidentes(unittest.TestCase):
    def test_so_quem_voltou_e_marca_bloqueio(self):
        al = [alerta("1.1.1.1", 10), alerta("1.1.1.1", 20), alerta("1.1.1.1", 30), alerta("2.2.2.2", 40), alerta("9.9.9.9", 5)]
        n, lista = dados.reincidentes(al, {"1.1.1.1"})
        self.assertEqual(n, 1)
        self.assertEqual(lista[0]["ip"], "1.1.1.1")
        self.assertEqual(lista[0]["alertas"], 3)
        self.assertTrue(lista[0]["banido"])

    def test_funil_conta_ips_com_decisao(self):
        al = [alerta("1.1.1.1", 10), alerta("1.1.1.1", 20), alerta("2.2.2.2", 40, ban=False)]
        f = dict(dados.resumir(al, al[:2], 1, AGORA)["funil"])
        self.assertEqual((f["Alertas"], f["IPs distintos"], f["IPs com bloqueio"], f["IPs reincidentes"]), (3, 2, 1, 1))


class Pico(unittest.TestCase):
    def serie(self, valores):
        return [{"n": n, "d": "h%d" % i} for i, n in enumerate(valores)]

    def test_detecta_pico(self):
        a = dados.anomalia(self.serie([2, 3, 2, 2, 3, 2, 30, 4]))
        self.assertEqual(a["quando"], "h6")
        self.assertGreater(a["fator"], 3)

    def test_sem_pico_em_serie_estavel_ou_curta(self):
        self.assertIsNone(dados.anomalia(self.serie([3, 4, 3, 4, 3, 4, 5, 4])))
        self.assertIsNone(dados.anomalia(self.serie([1, 40])))

    def test_pico_pequeno_demais_e_ignorado(self):
        self.assertIsNone(dados.anomalia(self.serie([0, 0, 0, 0, 0, 0, 3, 0])))


class Sites(unittest.TestCase):
    def test_peso_dividido_entre_hosts_do_alerta(self):
        a = alerta("1.1.1.1", 5, host="siapi.exemplo.com")
        a["events"] += [{"timestamp": a["start_at"], "meta": [{"key": "target_fqdn", "value": "ENSINO.exemplo.com"}]}]
        lista, ok = dados.por_dominio([a, alerta("2.2.2.2", 6, host="siapi.exemplo.com")])
        self.assertTrue(ok)
        self.assertEqual(dict(lista), {"siapi.exemplo.com": 1.5, "ensino.exemplo.com": 0.5})

    def test_sem_eventos_marca_indisponivel(self):
        lista, ok = dados.por_dominio([alerta("1.1.1.1", 5)])
        self.assertEqual((lista, ok), ([], False))

    def test_consulta_ip_traz_sites_e_serie_por_dia(self):
        al = [alerta("1.1.1.1", 10, host="photos.exemplo.com"), alerta("1.1.1.1", 60 * 30, host="photos.exemplo.com")]
        r = dados.consulta_ip("1.1.1.1", al, [])
        self.assertEqual(r["sites"], [("photos.exemplo.com", 2)])
        self.assertGreaterEqual(len(r["serie_dias"]), 2)
        self.assertEqual(sum(x["n"] for x in r["serie_dias"]), 2)


if __name__ == "__main__":
    unittest.main()
