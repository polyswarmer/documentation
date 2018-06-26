FROM ruby:2.5.1-stretch

ENV LANG C.UTF-8
ENV NODE_VERSION 8.11.3

WORKDIR /usr/src/app

COPY app/package*.json ./
COPY app/Gemfile* ./

RUN curl -s -o- https://raw.githubusercontent.com/creationix/nvm/v0.33.11/install.sh | bash && \
  export NVM_DIR="$HOME/.nvm" && \
  [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh" && \
  nvm install $NODE_VERSION && \
  nvm alias default $NODE_VERSION && \
  nvm use default && \
  npm install --silent && \
  bundle install --path vendor/bundle

COPY app .

CMD [ "bundle", "exec", "jekyll", "serve" ]
