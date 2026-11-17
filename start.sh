#!/bin/bash
# 本地直接跑（不用 systemd 时）
set -e
cd "$(dirname "$0")"
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
  .venv/bin/pip install -q -r requirements.txt
  .venv/bin/pip install -q --no-deps -e .
fi
[ -f .env ] || { echo "请先 cp .env.example .env 并填写"; exit 1; }
[ -f config.yaml ] || { echo "请先 cp config.example.yaml config.yaml 并填写"; exit 1; }
exec .venv/bin/python -m eipguard -c config.yaml "$@"
