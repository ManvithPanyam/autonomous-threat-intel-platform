#!/usr/bin/env bash
set -e

docker compose ps
curl -s http://localhost:8000/health