THIS_FILE := $(lastword $(MAKEFILE_LIST))

all:
	@$(MAKE) -f $(THIS_FILE) start
	@$(MAKE) -f $(THIS_FILE) npm-install
	@$(MAKE) -f $(THIS_FILE) bundle-install
	@$(MAKE) -f $(THIS_FILE) build

start:
	@bin/tasks/start.sh

npm-install:
	@bin/tasks/npm-install.sh

bundle-install:
	@bin/tasks/bundle-install.sh

build:
	@bin/tasks/build.sh

build-all:
	@bin/tasks/build-all.sh

build-prod:
	@bin/tasks/build-prod.sh

watch:
	@bin/tasks/watch.sh

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
	@echo "  - Starts container, installs dependencies, builds the project."
	@echo
	@echo "make start"
	@echo "  - Starts the container."
	@echo
	@echo "make npm-install"
	@echo "  - Runs npm install."
	@echo
	@echo "make bundle-install"
	@echo "  - Runs bundle install."
	@echo
	@echo "make build"
	@echo "  - Compiles the site using gulp."
	@echo
	@echo "make build-all"
	@echo "  - Compiles the site for all languages using gulp."
	@echo
	@echo "make build-prod"
	@echo "  - Compiles the site for all languages with the --production flag."
	@echo "  - To be used for pre-production testing."
	@echo
	@echo "make watch"
	@echo "  - Starts the project watcher."
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

.PHONY: start npm-install bundle-install build build-all build-prod watch test stop clean rebuild
