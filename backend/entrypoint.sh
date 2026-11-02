#!/bin/sh
set -eu
alembic -c backend/alembic.ini upgrade head
exec "$@"
