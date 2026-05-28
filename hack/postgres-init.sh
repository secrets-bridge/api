#!/bin/sh
# Postgres init hook that creates the dedicated test database used by
# pkg/storage/storage_test.go. Runs once on a fresh data volume.
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE DATABASE secrets_bridge_test;
EOSQL
