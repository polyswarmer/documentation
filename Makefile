THIS_FILE := $(lastword $(MAKEFILE_LIST))

all:
	@$(MAKE) -f $(THIS_FILE) start
	@$(MAKE) -f $(THIS_FILE) build
	@$(MAKE) -f $(THIS_FILE) watch

start:
	@bin/tasks/start.sh

build:
	@bin/tasks/build.sh

build-all:
	@bin/tasks/build-all.sh

build-prod:
	@bin/tasks/build-prod.sh

watch:
	@bin/tasks/watch.sh

npm-install:
	@bin/tasks/npm-install.sh

bundle-install:
	@bin/tasks/bundle-install.sh

test:
	@bin/tasks/test.sh

stop:
	@bin/tasks/stop.sh

clean:
	@bin/tasks/clean.sh

rebuild:
	@$(MAKE) -f $(THIS_FILE) stop
	@$(MAKE) -f $(THIS_FILE) clean
	@$(MAKE) -f $(THIS_FILE) all

help:
	@echo
	@echo "==== Jekyll Boilerplate ===="
	@echo
	@echo "make"
	@echo "  - Starts container, builds, and starts watcher."
	@echo
	@echo "make start"
	@echo "  - Starts the container."
	@echo
	@echo "make build"
	@echo "  - Compiles the site using gulp."
	@echo
	@echo "make build-all"
	@echo "  - Compiles the site for all languages using gulp."
	@echo
	@echo "make build-prod"
	@echo "  - Compiles the site for production using gulp."
	@echo
	@echo "make watch"
	@echo "  - Starts the project watcher."
	@echo
	@echo "make npm-install"
	@echo "  - Runs npm install."
	@echo
	@echo "make bundle-install"
	@echo "  - Runs bundle install."
	@echo
	@echo "make test"
	@echo "  - Runs all tests."
	@echo
	@echo "make stop"
	@echo "  - Stops the container."
	@echo
	@echo "make clean"
	@echo "  - Garbage collection."
	@echo
	@echo "make rebuild"
	@echo "  - Rebuild container from scratch."
	@echo

.PHONY: start build build-all build-prod watch npm-install bundle-install test stop clean rebuild
