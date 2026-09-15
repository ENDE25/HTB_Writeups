#!/bin/bash

# Script para sincronizar la carpeta Writeups con el repo de GitHub
# Uso: ./sync.sh "mensaje de commit opcional"

set -e

cd "$(dirname "$0")"

# Si no hay cambios, salimos sin hacer nada
if git diff --quiet && git diff --cached --quiet && [ -z "$(git status --porcelain)" ]; then
    echo "No hay cambios que subir."
    exit 0
fi

# Mensaje de commit: si se pasa como argumento se usa ese, si no, uno con fecha
if [ -n "$1" ]; then
    MENSAJE="$1"
else
    MENSAJE="Actualizacion $(date '+%Y-%m-%d %H:%M:%S')"
fi

git add .
git commit -m "$MENSAJE"
git push

echo "Sincronizado correctamente."
