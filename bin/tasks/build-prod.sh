#!/usr/bin/env bash

source bin/vars.sh

docker exec -it $CONTAINER bash -c "source ~/.bashrc && \
  npx gulp --all-langs --production"
