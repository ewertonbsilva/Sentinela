# Autenticação do Sentinela

O Sentinela não tem banco de usuários. O login é um **bind LDAP** com o usuário e a senha digitados na tela, feito por **LDAPS** (TLS) com o certificado do servidor **fixado**. Se o servidor aceitar, o painel lê o atributo `memberOf` da própria entrada do usuário e decide se ele pode entrar. Nenhuma senha é gravada.

## Quem entra

Entra quem satisfizer **uma** destas condições:

1. tem o grupo de `ALLOWED_GROUP` no `memberOf` (DN completo do grupo, comparado sem diferenciar maiúsculas);
2. está em `ALLOWED_USERS` (logins avulsos, opcional);
3. está em `UNBAN_USERS` (quem pode liberar IPs também entra no painel).

Sem `ALLOWED_GROUP`, `ALLOWED_USERS` e `UNBAN_USERS`, ninguém entra. Se o seu servidor LDAP não devolve `memberOf` para o próprio usuário, use `ALLOWED_USERS`.

## Configuração mínima

```ini
LDAP_HOST=ldap.exemplo.com
LDAP_PORT=636
LDAP_BASE=ou=people,dc=exemplo,dc=com
LDAP_USER_DN=uid={usuario},{base}
LDAP_CA=/opt/sentinela/ldap-ca.crt
LDAP_NAME=ldap.exemplo.com
ALLOWED_GROUP=cn=sentinela,ou=groups,dc=exemplo,dc=com
```

`{usuario}` é o login digitado (já escapado conforme o RFC 4514) e `{base}` é o `LDAP_BASE`. Exemplos de `LDAP_USER_DN`:

| Servidor | Molde |
|---|---|
| OpenLDAP / 389-ds (padrão) | `uid={usuario},{base}` |
| FreeIPA | `uid={usuario},cn=users,cn=accounts,dc=exemplo,dc=com` |
| Active Directory (UPN) | `{usuario}@exemplo.com` |

No Active Directory o atributo de grupos é `memberOf` também, mas a busca usa `(uid=...)`; se o seu AD não tiver `uid`, entre pelo `ALLOWED_USERS` ou abra uma *issue* descrevendo o seu esquema.

## Obter o certificado do LDAP

O certificado é **fixado**: o painel só conversa com um servidor que apresente uma cadeia assinada por ele. Para pegar o certificado do servidor:

```bash
openssl s_client -connect ldap.exemplo.com:636 -servername ldap.exemplo.com </dev/null 2>/dev/null \
  | openssl x509 > /opt/sentinela/ldap-ca.crt
```

Se o servidor usa uma CA interna, prefira o certificado **da CA**, não o do servidor (assim a renovação do certificado não derruba o login).

> O `ldap3` rodando no Python 3.12 ou mais novo **não valida endereço IP** no campo SAN do certificado. Por isso o painel confere o **nome DNS** informado em `LDAP_NAME`. Use um nome que conste no certificado.

## Dois servidores LDAP

Para dois sites, use `BROKER_A_*` e `BROKER_B_*` (veja o `.env.example`). O painel tenta primeiro o servidor cuja rede (`BROKER_x_REDES`) contém o IP de quem entra e só passa ao outro se o primeiro não responder. Senha recusada é definitiva: não tenta no outro servidor.

## Sessão

- Cookie assinado (HMAC-SHA256) com o `PAINEL_SECRET`, `HttpOnly`, `SameSite=Strict`, `Secure`.
- Expira por inatividade (`IDLE_SECONDS`, 15 min) e por idade (`MAX_LIFE_SECONDS`, 8 h).
- "Lembrar de mim": cookie persistente por `REMEMBER_DAYS` dias (0 desliga a opção).
- Trocar o `PAINEL_SECRET` encerra todas as sessões.

## Liberar IP

A única ação de escrita do painel. Exige: estar em `UNBAN_USERS`, a senha de liberação (guardada só como hash PBKDF2 em `UNBAN_HASH`, definida com `deploy/senha-liberacao.sh`), um motivo e um único endereço IP válido. Há limite de tentativas e cada liberação fica registrada com o login de quem a fez.
