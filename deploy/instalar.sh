#!/bin/bash
# Instala o Sentinela no host que roda o CrowdSec (e o proxy reverso). Como root, de dentro da pasta do projeto:
#   sudo ./deploy/instalar.sh
# Pode rodar de novo para atualizar: preserva o .env existente e so atualiza os arquivos do programa.
set -euo pipefail

DEST=/opt/sentinela
USUARIO=sentinela
ORIGEM="$(cd "$(dirname "$0")/.." && pwd)"

[ "$(id -u)" = 0 ] || { echo "Rode com sudo."; exit 1; }
command -v cscli >/dev/null || { echo "cscli nao encontrado: instale o CrowdSec neste host antes."; exit 1; }
command -v python3 >/dev/null || { echo "python3 nao encontrado."; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || { echo "Precisa de Python 3.10 ou mais novo."; exit 1; }

id "$USUARIO" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$USUARIO"

install -d -m 755 "$DEST"
cp -r "$ORIGEM/painel.py" "$ORIGEM/dados.py" "$ORIGEM/static" "$DEST/"
chown -R root:root "$DEST"
chmod -R go-w "$DEST"

# Dependencia: ldap3. Tenta o pacote do sistema; senao, instala numa pasta propria (./lib), sem mexer no Python do sistema.
if ! python3 -c 'import ldap3' 2>/dev/null && ! [ -d "$DEST/lib/ldap3" ]; then
  if command -v apt-get >/dev/null && apt-get install -y python3-ldap3 >/dev/null 2>&1; then
    echo "ldap3 instalado pelo apt (python3-ldap3)"
  elif python3 -m pip --version >/dev/null 2>&1 && python3 -m pip install --quiet --target "$DEST/lib" -r "$ORIGEM/requirements.txt"; then
    echo "ldap3 instalado em $DEST/lib"
  else
    echo "AVISO: nao consegui instalar o ldap3. Instale 'python3-ldap3' (apt) ou rode: pip install --target $DEST/lib -r requirements.txt"
  fi
fi

if [ ! -f "$DEST/.env" ]; then
  SECRET="$(openssl rand -hex 32)"
  SENHA="$(openssl rand -hex 24)"
  # Maquina propria na LAPI (credencial separada da do agente); --force recria se ja existir
  cscli machines add sentinela --password "$SENHA" --force -f /dev/null >/dev/null
  umask 077
  sed -e "s|^PAINEL_SECRET=.*|PAINEL_SECRET=$SECRET|" \
      -e "s|^LAPI_PASSWORD=.*|LAPI_PASSWORD=$SENHA|" \
      "$ORIGEM/.env.example" > "$DEST/.env"
  chown root:"$USUARIO" "$DEST/.env"
  chmod 640 "$DEST/.env"
  echo ".env criado em $DEST/.env"
else
  # Atualizacao: acrescenta as chaves novas do .env.example que o .env existente ainda nao tem (sem tocar nas existentes)
  grep -E '^[A-Z_]+=' "$ORIGEM/.env.example" | while IFS= read -r linha; do
    chave="${linha%%=*}"
    grep -q "^${chave}=" "$DEST/.env" || { echo "$linha" >> "$DEST/.env"; echo ".env: chave nova adicionada: $chave"; }
  done
fi

# Chave de bouncer (opcional) para consultar decisoes por IP, inclusive as da lista da comunidade (so leitura)
if ! grep -q '^BOUNCER_KEY=.\+' "$DEST/.env"; then
  cscli bouncers delete sentinela-web >/dev/null 2>&1 || true
  CHAVE="$(cscli bouncers add sentinela-web -o raw 2>/dev/null | tail -n1 || true)"
  if [ -n "$CHAVE" ]; then
    sed -i "s|^BOUNCER_KEY=.*|BOUNCER_KEY=$CHAVE|" "$DEST/.env"
    echo "bouncer 'sentinela-web' criado (consulta de decisoes por IP ativada)"
  else
    echo "AVISO: nao consegui criar o bouncer; a consulta de decisoes por IP ficara desativada"
  fi
fi

# Descricoes dos cenarios/parsers do hub: sao arquivos publicos do hub do CrowdSec, so nao vinham legiveis para outros usuarios
if [ -d /etc/crowdsec/hub ]; then chmod -R o+rX /etc/crowdsec/hub && echo "hub do CrowdSec liberado para leitura (descricoes na aba Cenarios)"; fi

install -m 644 "$ORIGEM/deploy/sentinela.service" /etc/systemd/system/sentinela.service
systemctl daemon-reload
systemctl enable sentinela >/dev/null 2>&1

# O LDAP precisa ser configurado por voce: enquanto o .env tiver os valores de exemplo, nao inicia o servico.
if grep -qE '^(LDAP_HOST=ldap\.exemplo\.com|ALLOWED_GROUP=cn=sentinela,ou=groups,dc=exemplo,dc=com)' "$DEST/.env"; then
  echo
  echo "Falta configurar o login. Edite $DEST/.env (secao 'Autenticacao' e 'Quem entra'),"
  echo "coloque o certificado do LDAP em LDAP_CA e depois rode:  sudo systemctl restart sentinela"
  exit 0
fi

systemctl restart sentinela
sleep 2
echo "--- verificacao"
systemctl is-active sentinela
set -a; . "$DEST/.env"; set +a
curl -s -m 5 "http://$PAINEL_BIND:$PAINEL_PORT${PAINEL_BASE:-}/saude" && echo
# a credencial da maquina precisa funcionar na LAPI
COD=$(curl -s -m 8 -o /dev/null -w '%{http_code}' -X POST "$LAPI_URL/v1/watchers/login" \
  -H 'Content-Type: application/json' \
  -d "{\"machine_id\":\"$LAPI_MACHINE\",\"password\":\"$LAPI_PASSWORD\",\"scenarios\":[]}")
echo "login da maquina na LAPI: HTTP $COD (esperado 200)"
echo
echo "Proximo passo: publique http://$PAINEL_BIND:$PAINEL_PORT no seu proxy reverso, com HTTPS (veja o README)."
