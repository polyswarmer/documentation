# PolySwarm Documentation

PolySwarm Documentation Source Code

## Requirements

[Docker CE](https://www.docker.com/community-edition)

---

## Getting Started

### Make

This project uses a Makefile to abstract all of the Docker commands you will need.

To see a list of all of the available commands:

    $ make help

### Building the image

To build the Docker image, start the container, build the site with Gulp, and start the project watcher all in one shot:

    $ make

---

## Development

### Starting the container

To simply build the image and start the container:

    $ make start

### Building the site

To simply build the site with Gulp:

    $ make build

### Watching the project

To simply watch the project files:

    $ make watch

### Running npm install

To run an npm install if your package.json has changed:

    $ make npm-install

### Running bundle install

To run a bundle install if your Gemfile has changed:

    $ make bundle-install

---

## Production

### Building for production

To build the site for prouduction using Gulp:

    $ make build-prod

---

## Stopping and Cleanup

### Stopping the container

To stop the container:

    $ make stop

### Cleanup

To run a docker system prune and remove the container and image:

    $ make clean
