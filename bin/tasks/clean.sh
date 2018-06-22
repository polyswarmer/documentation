#!/usr/bin/env bash

set -e

source bin/vars.sh

# Is the container still running?
if [[ $(docker inspect -f {{.State.Running}} $CONTAINER) == "true" ]]; then
  echo "Your container is still running. Please run make stop before running clean."
  exit 1
else
  # Are you sure you want to?
  printf "Are you sure you want to prune your system and delete the image? [y/N] "
  read -r PROCEED
  if [[ $PROCEED == "y" ]] || [[ $PROCEED == "Y" ]]; then
    # Clean it up!
    docker system prune
    docker rmi $IMAGE
    cd app && rm -rf tmp dist node_modules vendor .sass-cache
  else
    # Abort
    echo "OK. Aborting..."
    exit 0
  fi
fi
