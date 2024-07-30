#!/bin/sh

STATIC="./server/static"

mkdir -p "${STATIC}/files/"
cp -f "./client/start_sploit.py" "${STATIC}/files/"

docker compose up --build $@
