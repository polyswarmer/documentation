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

To start the container, install the project dependencies, and build the site with Gulp:

    $ make

### Watching the project

To start the project watcher:

    $ make watch

---

## Development

### Starting the container

To simply start the container:

    $ make start

### Building the site

To simply build the site with Gulp:

    $ make build

### Running npm install

To run an npm install if your package.json has changed:

    $ make npm-install

### Running bundle install

To run a bundle install if your Gemfile has changed:

    $ make bundle-install

---

## i18n

### Building for all langages

To build the site with all languages using Gulp:

    $ make build-all

---

## Production

### Building for production

To build the site for prouduction using Gulp:

    $ make build-prod

---

## Testing

### Run all tests

To run all tests:

    $ make test

---

## Stopping and Cleanup

### Stopping the container

To stop the container:

    $ make stop

### Cleanup

To run a docker system prune and remove the container and image:

    $ make clean

### Rebuilding the container

If you would like to system prune and rebuild the container from scratch:

    $ make rebuild

---

## Continuous Integration

### GitLab

#### Caching

To clear the GitLab cache, increment the cache key in the `gitlab-ci.yml` file.
