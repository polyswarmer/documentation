#!/usr/bin/env bash

cd app

source ~/.bashrc

if [ ! -e node_modules ]; then
  npm install --silent;
fi

bundle install --path vendor/bundle

npx gulp --all-langs --production
