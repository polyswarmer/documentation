#!/usr/bin/env bash

source bin/vars.sh

docker exec -it $CONTAINER bash -c "source ~/.bashrc && \
  bundle check || bundle install --path vendor/bundle"
