#!/usr/bin/env bash
# Deploy VoiceAI → NAS (ersetzt git pull am NAS)
# Aufruf: bash deploy.sh

NAS="//DXP4800PRO-4AFA/docker/voiceai"
SRC="$(cd "$(dirname "$0")" && pwd)"

echo "Deploying $SRC → $NAS"

cp "$SRC/backend/app.py"        "$NAS/backend/app.py"       && echo "  ✓ backend/app.py"
cp "$SRC/frontend/index.html"   "$NAS/frontend/index.html"  && echo "  ✓ frontend/index.html"
cp "$SRC/docker-compose.yml"    "$NAS/docker-compose.yml"   && echo "  ✓ docker-compose.yml"
cp "$SRC/Dockerfile"            "$NAS/Dockerfile"            && echo "  ✓ Dockerfile"

# docs/ komplett synchronisieren
for f in "$SRC/docs/"*.md; do
    fname=$(basename "$f")
    cp "$f" "$NAS/docs/$fname" && echo "  ✓ docs/$fname"
done

echo "Done."
