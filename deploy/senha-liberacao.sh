#!/bin/bash
# Define (ou troca) a senha de liberacao de IPs do painel. Uso, no host:  sudo ./deploy/senha-liberacao.sh
# A senha e digitada aqui (sem aparecer na tela) e SO o hash PBKDF2 vai para o .env; ela nunca e gravada.
set -euo pipefail
DEST=/opt/sentinela
[ "$(id -u)" = 0 ] || { echo "Rode com sudo."; exit 1; }
[ -f "$DEST/.env" ] || { echo "Instale o painel antes (deploy/instalar.sh)."; exit 1; }
LINHA="$(python3 "$DEST/painel.py" --gerar-hash)"
case "$LINHA" in UNBAN_HASH=pbkdf2_sha256:*) ;; *) echo "Nao foi possivel gerar o hash."; exit 1;; esac
if grep -q '^UNBAN_HASH=' "$DEST/.env"; then sed -i "s|^UNBAN_HASH=.*|$LINHA|" "$DEST/.env"; else echo "$LINHA" >> "$DEST/.env"; fi
systemctl restart sentinela
echo "Senha de liberacao definida e painel reiniciado."
echo "Quem pode liberar: $(grep '^UNBAN_USERS=' "$DEST/.env" | cut -d= -f2)"
