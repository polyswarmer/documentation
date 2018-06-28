#!/usr/bin/env bash

cd app

source ~/.bashrc

npm install --silent;

bundle install --path vendor/bundle

npx gulp --all-langs --production
