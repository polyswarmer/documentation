#!/usr/bin/env bash

cd app

source ~/.bashrc

bundle install --path vendor/bundle

npx retire -n -p

bundle exec htmlproofer ./dist --check-html --url-ignore '/#.*/' --disable-external
