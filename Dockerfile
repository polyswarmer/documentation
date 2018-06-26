FROM ruby:2.5.1-stretch

ENV LANG C.UTF-8
ENV NODE_VERSION 8.11.3

WORKDIR /usr/src/app

COPY bin/docker/init.sh /usr/local/bin/

RUN mkdir -p ../tmp && echo "Server is running..." >> ../tmp/index.html && \
  curl -s -o- https://raw.githubusercontent.com/creationix/nvm/v0.33.11/install.sh | bash && \
  export NVM_DIR="$HOME/.nvm" && \
  [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh" && \
  nvm install $NODE_VERSION && \
  nvm alias default $NODE_VERSION && \
  nvm use default

CMD [ "/usr/local/bin/init.sh" ]
