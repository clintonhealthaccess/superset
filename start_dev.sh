#!/usr/bin/env bash

export DOCKER_TLS_VERIFY="1"
export DOCKER_HOST="tcp://34.207.216.185:2376"
export DOCKER_CERT_PATH="${PWD}/credentials/dev_env"
export COMPOSE_INTERACTIVE_NO_CLI=1

/usr/bin/docker-compose -f docker-compose-non-dev.yml kill
/usr/bin/docker-compose -f docker-compose-non-dev.yml down
/usr/bin/docker-compose -f docker-compose-non-dev.yml pull
# /usr/bin/docker-compose -f docker-compose-non-dev.yml up -d

docker cp docker superset_app:/app/.