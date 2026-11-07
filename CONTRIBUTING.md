# Contribuindo com o Sentinela

Obrigado pelo interesse! Ideias, relatos de erro e *pull requests* são bem-vindos.

## Antes de começar

- Abra uma *issue* descrevendo o problema ou a ideia, principalmente para mudanças grandes.
- **Falha de segurança?** Não abra *issue* pública: veja [SECURITY.md](SECURITY.md).
- **Nunca** envie dados reais: IPs, nomes de máquinas, usuários, caminhos acessados ou saídas do CrowdSec da sua rede. Use exemplos fictícios (faixas de documentação como `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, e domínios `exemplo.com`).

## Ambiente de desenvolvimento

É Python 3.10+ da biblioteca padrão e JavaScript puro. A única dependência é o `ldap3` (`pip install -r requirements.txt`), que os testes de login usam de forma simulada: nenhum teste fala com um LDAP de verdade.

```bash
git clone <url-do-repositorio> sentinela && cd sentinela
pip install -r requirements.txt
python -m unittest -v
for f in static/*.js; do node --check "$f"; done     # opcional, precisa do Node só para checar a sintaxe
```

Para ver o painel com dados fictícios, sem CrowdSec nem LDAP:

```bash
PAINEL_DEMO=1 PAINEL_BIND=127.0.0.1 COOKIE_SECURE=0 PAINEL_BASE= \
PAINEL_SECRET=$(python -c "import secrets;print(secrets.token_hex(32))") python painel.py
# abra http://127.0.0.1:8088 e entre com o usuário "demo" e a senha "demo" (só no modo demonstração)
```

## O que esperamos de um *pull request*

1. **Testes.** Toda regra nova precisa de um teste. Toda correção de erro, de um teste que falhava antes.
2. **Segurança primeiro.** Em especial:
   - texto vindo do servidor ou da rede entra na tela por `textContent`, **nunca** por `innerHTML`;
   - o painel continua **somente leitura**, exceto a liberação de IP e seus controles;
   - sem segredos em código, em log ou em resposta.
3. **Sem dependências novas** no servidor nem no navegador (sem CDN, sem fontes externas). O `ldap3` é a única exceção.
4. **Mudanças pequenas e focadas**, com uma mensagem de *commit* que explique o porquê.
5. Atualize o `README.md` e o `.env.example` se mudar a configuração.

## Estilo

- Código e comentários em português; nomes de variáveis em português sem acento.
- Mensagens na interface em português do Brasil, com a acentuação correta.
- Linhas de até ~130 caracteres; sem formatadores automáticos obrigatórios.
- Arquivos com final de linha LF.
