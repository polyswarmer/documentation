# PolySwarm Documentation

PolySwarm Documentation Source Code

## Adding and Localizing Content

User-contributed content should be placed in two folders, `public-src` and `_i18n` (more on localization in a moment).

Create a file in `public-src/pages`. The contents of that file should look something like this:

`public-src/pages/example.md`
```markdown
---
title: pages.example.title
description: pages.example.description
permalink: /example/
---

{% translate_file example.md %}
```

As you can see, this file simply points to the localized YAML and Markdown files found in the `_i18n` directory.

You should then have a `[lang].yml` file and a `[lang]/example.md` file. For english content, it would look like this:

`_i18n/en.yml`
```yml
pages:
  example:
    title: My Example Page
    description: This is my example page.
```

`_i18n/en/example.md`
```markdown
## Example

This is my example markdown file.
```

Now, visiting `/example` will display "This is my example page.".

You can then copy these files into the other language directories to be translated.

## Navigation

Navigation items can be edited in the `[lang].yml` file.

Add `root: true` to an item if you do not want the url to be localized.

You can also add `subitems: (name: string, [array of items])` to create a dropdown.

## Headings and Sidebar Navigation

The sidebar navigation is generated automatically from the Level 2 (h2) and Level 3 (h3) headings on the page.

```markdown
  ## Main section

  ### Subsection
```

Level 1 (h1) headings should not be used as an h1 is already used in the header.

## Special Markdown Cases

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
