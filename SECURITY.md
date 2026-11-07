# Política de segurança

## Reportando uma vulnerabilidade no Sentinela

Se você achou uma falha de segurança **no Sentinela** (por exemplo: contornar o login, liberar um IP sem autorização, injeção, XSS, vazamento de dados), **não abra uma *issue* pública**.

Use o recurso de **relato privado de vulnerabilidades do GitHub** (aba *Security* do repositório, "Report a vulnerability"). Se ele não estiver disponível, entre em contato com os mantenedores por um canal privado indicado no perfil do repositório.

Inclua, se puder: a versão (ou o *commit*), como reproduzir, o impacto que você enxerga e, se houver, uma sugestão de correção. Pedimos um prazo razoável para corrigir antes da divulgação pública.

## O que está no escopo

- Autenticação, sessão e autorização do painel (login LDAP, grupo permitido, cookie assinado).
- A **única ação de escrita**, "liberar IP": senha de liberação, limite de tentativas, validação do endereço e registro de auditoria.
- Qualquer caminho em que dado vindo da rede (caminho pedido, *user-agent*, nome de host) vire **HTML**, **comando** ou **consulta** sem validação.
- Vazamento de segredos (`.env`, senhas, chaves) em logs, respostas ou arquivos.
- O instalador e a *unit* do systemd.

## Fora do escopo

- Falhas **no CrowdSec**, no `ldap3` ou no seu proxy reverso: reporte aos projetos deles.
- Ataques que exigem acesso de administrador ao servidor onde o Sentinela roda.
- Painel exposto à internet sem as proteções recomendadas no README (HTTPS, `ALLOWED_IPS`, grupo restrito).

## Princípios de projeto

- O painel é **somente leitura**, com uma exceção: liberar um IP bloqueado, que exige login, permissão própria, senha de liberação e deixa registro.
- Tudo que vem de fora entra na tela por `textContent`, nunca por `innerHTML`; a política de conteúdo (CSP) bloqueia scripts que não sejam do próprio painel.
- Login por LDAPS com certificado **fixado**; nenhuma senha é guardada.
- A sessão é um cookie assinado (`HttpOnly`, `SameSite=Strict`, `Secure`), sem estado no servidor.
- Segredos ficam no `.env` (fora do repositório) e nunca em log.

Se você encontrar algo que contradiz esses princípios, é uma falha que queremos corrigir.

## Boas práticas para quem instala

- Publique o painel **apenas** com HTTPS e, se possível, limite por rede (`ALLOWED_IPS` ou controle de acesso do proxy).
- Restrinja o acesso a um grupo pequeno (`ALLOWED_GROUP`).
- Defina uma senha de liberação longa e única (`deploy/senha-liberacao.sh`).
- Os dados do painel (IPs, caminhos acessados) são sensíveis: não compartilhe capturas de tela sem revisar.
- Mantenha o CrowdSec, o Python e o sistema atualizados.
