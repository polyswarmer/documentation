#!/usr/bin/env bash

source bin/vars.sh

docker exec -it $CONTAINER bash -c "source ~/.bashrc && \
  bundle exec htmlproofer $PROJECT_DEST \
    --check-html \
    --url-ignore '/#.*/' \
    --disable-external"
