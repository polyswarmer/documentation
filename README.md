# PolySwarm Documentation

PolySwarm Documentation (https://docs.polyswarm.io) is a public resource designed to help Experts, Arbiters, Ambassadors, and more get to know PolySwarm products.

## Branch Level

### master

The pages here is regarded as public/authentic.
Not any articles under development or incomplete state should be located here.

### develop

This branch is pre-master branch which enhances development-phase articles.
Once the branch is ready for release, it will be merged into master.

## Adding an English Page to the Docs

PolySwarm Documentation is availble in many target languages, however, the source language for all content is English.
This section will show you how to add English content that will then be availbe for translation.

A new English page can be added in four steps:

1. [Add Your Localized Title](https://github.com/polyswarm/documentation#step-one-add-your-localized-title)
1. [Add Your Localized Content](https://github.com/polyswarm/documentation#step-two-add-your-localized-content)
1. [Reference Your Localized Title and Content](https://github.com/polyswarm/documentation#step-three-reference-your-localized-title-and-content)
1. [Add Your Page to the Navigation](https://github.com/polyswarm/documentation#step-four-add-your-page-to-the-navigation)

### Step One: Add Your Localized Title

Since the documentation will be available in multiple languages, we need to define the title of our page in a special file that keeps track of all localized content.
That file is `_i18n/en.yml`, which as you can see is a [YAML](https://en.wikipedia.org/wiki/YAML) file containing key value pairs.

In `_i18n/en.yml`, you will see a section called `docs`.
There, add a unique key for your page and then add your title within that key like so:

```yml
docs:
  my_unique_page_key:
    title: My Page Title
```

### Step Two: Add Your Localized Content

Now that we've created our title, let's create the localized file that will hold our content.

In `_i18n/en/_docs`, create a new [Markdown](https://github.com/polyswarm/documentation#markdown) file with the following format:

```
my-page-title.md
```

Within that file, add your Markdown content:

```markdown
## Top-Level Section

This is a top-level section in my new example page.

### Subsection

This is a subsection of my top-level section.
```

As you can see, because our title will render as an level 1 heading (h1), we want to use level 2 headings (h2) for our top-level sections.
Any subsection will be a level 3 heading (h3). This way, the sidebar nav will render properly and be easy for users to navigate.

#### Images

Images should be placed in the `public-src/images` directoy and referenced like so:

```markdown
![example image](/public-src/images/example.png)
```

Images should be no more than about 720px wide and should be optimized before they are uploaded, using a tool like [TinyPNG](https://tinypng.com/).

### Step Three: Reference Your Localized Title and Content

Now that we have added a localized title and have created our localized content, it's time to add our page to the site.

To add your page to the site, create a file in `public-src/_docs` with the following format:

```
YYYY-MM-DD-my-page-title.md
```

As you can see, we are adding the date here to maintain page order.
If you need to re-arrange the page order, simply adjust the dates accordingly.

Within that file, reference your localized title and content:

```markdown
---
title: docs.my_unique_page_key.title
---

{% tf _docs/my-page-title.md %}
```

The section between the triple-dashed lines is the [YAML front matter](https://jekyllrb.com/docs/frontmatter/) block.

As you can see, the front matter block [references the localized title](https://github.com/Anthony-Gaudino/jekyll-multiple-languages-plugin#54-i18n-in-templates) you defined in `_i18n/en.yml`.

The content within the curly braces and percentage signs [references the localized content](https://github.com/Anthony-Gaudino/jekyll-multiple-languages-plugin#52-including-translated-files) from your Markdown file in `_i18n/en/_docs`.

### Step Four: Add Your Page to the Navigation

Navigation items can be added or removed in the `_i18n/en.yml` file.
There, you will see a key called `header` with a property called `navigation`. You can also see that `navigation` has a property called `items` which is an array of navigation items.

Navigation items have the following format:

```yml
- name: My Page Title
  url: /my-page-title/
  root:  bool # (optional) If true, url will NOT be localized
  rooturl: bool # (optional) If true, baseurl will be https://polyswarm.io
```

You can also create a nav item with a dropdown list of subitems (where subitems is an array of items) like so:

```yml
- name: My Dropdown Title
  subitems:
  - name: My Page Title
    url: /my-page-title/
    root:  bool # (optional) If true, url will NOT be localized
    rooturl: bool # (optional) If true, baseurl will be https://polyswarm.io
```

Congratulations! Now that you have added your page to the navigation, your page is ready to be deployed and translated.

## Translation

Initial content is all created in English.
We use [Crowdin](https://crowdin.com) to manage translation.
Non-English files are automatically generated by Crowdin, so it is best not to edit non-English files directly.
If you want to help translate the PolySwarm documentation, please [sign-up as a Crowdin translator](https://crwd.in/polyswarm-documentation) for our project.
If you want to translate this documentation into a language that our Crowdin project is not configured for, let us know, we can add more languages.

## Markdown

Markdown follows the [Github-flavored Markdown](https://github.com/adam-p/markdown-here/wiki/Markdown-Cheatsheet) style.

### Special Cases

#### Callouts

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

#### Flags

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

#### Videos

When embedding a YouTube video, it is best to wrap the embed code in a video wrapper using a div with the class of `h-video-wrapper` to make for a responsive embed.

```html
<div class="h-video-wrapper">
  <iframe width="560" height="315" src="https://www.youtube.com/embed/dQw4w9WgXcQ?showinfo=0&rel=0" frameborder="0" allow="autoplay; encrypted-media" allowfullscreen></iframe>
</div>
```

#### Collapsible Markdown

```html
<details markdown="1">

  <summary>Toggle Button</summary>

  some markdown to reveal

</details>
```
