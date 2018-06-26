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

---

## Development

### Starting the container

To simply start the container:

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

## Stopping and Cleanup

### Stopping the container

To stop the container:

    $ make stop

### Cleanup

To run a docker system prune and remove the container and image:

    $ make clean

---

## Stopping and Cleanup

### Rebuilding the container

If you would like to system prune and rebuild the container from scratch:

    $ make rebuild

---

## Markdown

### Callouts

Callouts are text boxes which are used to emphasize important content.

```html
<div class="m-callout m-callout--info">
  <p><strong>Lorem ipsum dolor sit amet</strong></p>
  <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>
  <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>
</div>
```

Style Classes:
* `m-callout` - Grey
* `m-callout m-callout--info` - Purple
* `m-callout m-callout--warning` - Yellow
* `m-callout m-callout--danger` - Red
* `m-callout m-callout--success` - Green

### Callouts

Flags are also text boxes which are used to emphasize important content, but are stylistically different.

```html
<div class="m-flag m-flag--danger">
  <p><strong>Lorem ipsum dolor sit amet</strong></p>
  <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>
  <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>
</div>
```

Style Classes:
* `m-flag` - Purple
* `m-flag m-flag--warning` - Yellow
* `m-flag m-flag--danger` - Red
* `m-flag m-flag--success` - Green

### Videos

When embedding a YouTube video, it is best to wrap the embed code in a video wrapper using a div with the class of `h-video-wrapper` to make for a responsive embed.

```html
<div class="h-video-wrapper">
  <iframe width="560" height="315" src="https://www.youtube.com/embed/dQw4w9WgXcQ?showinfo=0&rel=0" frameborder="0" allow="autoplay; encrypted-media" allowfullscreen></iframe>
</div>
```
