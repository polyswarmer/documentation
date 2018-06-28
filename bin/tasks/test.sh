#!/usr/bin/env bash

source bin/vars.sh

docker exec -it $CONTAINER bash -c "source ~/.bashrc && \
  echo 'Building for all languages...' && \
  npx gulp --all-langs --production && \
  echo && \
  echo 'Checking for vulnerabilities...'
  npx retire -n -p && \
  echo && \
  bundle exec htmlproofer $PROJECT_DEST \
    --check-html \
    --url-ignore '/#.*/' \
    --disable-external"
