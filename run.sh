#!/usr/bin/env bash
#
# Wrapper para baixar e executar o inventario_akv.py no Azure Cloud Shell.
#
# Uso rápido (one-liner):
#   curl -fsSL https://raw.githubusercontent.com/wesleyit/inventario_akv/main/run.sh | bash
#
# Ele baixa o script Python mais recente e o executa com o Python nativo,
# redirecionando a entrada para o terminal para que os prompts interativos
# (continuar/recomeçar) funcionem mesmo quando chamado via 'curl | bash'.

set -euo pipefail

URL_SCRIPT="https://raw.githubusercontent.com/wesleyit/inventario_akv/main/inventario_akv.py"
ARQUIVO_LOCAL="inventario_akv.py"

echo "Baixando ${ARQUIVO_LOCAL}..."
curl -fsSL "${URL_SCRIPT}" -o "${ARQUIVO_LOCAL}"

echo "Executando o inventário..."
# Redireciona a entrada padrão para o terminal, garantindo que o input()
# funcione mesmo quando este script chega via pipe (curl | bash).
if [[ -e /dev/tty ]]; then
  python3 "${ARQUIVO_LOCAL}" < /dev/tty
else
  python3 "${ARQUIVO_LOCAL}"
fi
