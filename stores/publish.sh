#!/bin/bash
# Publica una carpeta en la rama scan-results, bajo results/<nombre>/.
# Uso: stores/publish.sh <nombre> <carpeta> [cifrar=1]
# Con cifrar=1 la carpeta va como findings.tgz.enc + key.enc (el repo es público;
# solo descifra quien tiene la clave privada de deep-scan/results-pubkey.pem).
set -u
NAME=$1; SRC=$2; ENC=${3:-1}
REPO="https://x-access-token:${GH_TOKEN}@github.com/${GITHUB_REPOSITORY}"
PUB="$(pwd)/deep-scan/results-pubkey.pem"
stage=$(mktemp -d)
cp "$SRC"/summary.json "$stage/" 2>/dev/null || true
tail -n 30 "$SRC"/progress.log > "$stage/progress.txt" 2>/dev/null || true
if [ "$ENC" = "1" ]; then
  tar -czf "$stage/f.tgz" -C "$SRC" . 2>/dev/null
  openssl rand -hex 32 > "$stage/k"
  openssl enc -aes-256-cbc -pbkdf2 -salt -in "$stage/f.tgz" -out "$stage/findings.tgz.enc" -pass file:"$stage/k"
  openssl pkeyutl -encrypt -pubin -inkey "$PUB" -pkeyopt rsa_padding_mode:oaep -in "$stage/k" -out "$stage/key.enc"
  rm -f "$stage/f.tgz" "$stage/k"
else
  cp -r "$SRC"/. "$stage/"
fi
for attempt in 1 2 3 4 5 6; do
  w=$(mktemp -d)
  if git clone -q --depth 1 --branch scan-results "$REPO" "$w" 2>/dev/null; then :; else
    git -C "$w" init -q && git -C "$w" checkout -q --orphan scan-results
  fi
  rm -rf "$w/results/$NAME" && mkdir -p "$w/results/$NAME" && cp -r "$stage"/. "$w/results/$NAME/"
  git -C "$w" add -A
  git -C "$w" -c user.name=store-scan -c user.email=store-scan@users.noreply.github.com commit -qm "resultados $NAME" || exit 0
  if git -C "$w" push -q "$REPO" HEAD:refs/heads/scan-results 2>/dev/null; then exit 0; fi
  sleep $((attempt * 3 + RANDOM % 5))
done
echo "::warning::no se pudo publicar $NAME"
