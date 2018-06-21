module.exports = (() => {
  const project = {
    src: './src',
    dest: './dist',
    assets: './dist/assets',
    theme: './src/theme'
  };

  const rev = {
    manifest: `${project.assets}/rev-manifest.json`
  };

  const jekyll = {
    dest: './tmp',
    watchFiles: ['_config.yml', `${project.theme}/**/*`, `${project.publicSrc}/**/*`],
    head: [`${project.theme}/_includes/l-head.html`],
    foot: [`${project.theme}/_includes/l-scripts.html`]
  };

  const styles = {
    src: `${project.src}/styles`,
    dest: `${project.assets}/styles`,
    pattern: '/**/*.scss'
  };

  const scripts = {
    src: `${project.src}/scripts`,
    dest: `${project.assets}/scripts`,
    pattern: '/**/*.js',
    vendorEntries: {
      vendor: ['jquery']
    },
    mainEntries: {
      app: `${project.src}/scripts/app.js`
    },
    providePlugins: {
      $: 'jquery',
      jQuery: 'jquery'
    }
  };

  const images = {
    src: `${project.src}/images`,
    dest: `${project.assets}/images`,
    pattern: '/**/*.{gif,ico,jpeg,jpg,png,svg,webp}'
  };

  const fonts = {
    src: `${project.src}/fonts`,
    dest: `${project.assets}/fonts`,
    pattern: '/**/*.{eot,svg,ttf,woff,woff2,otf}'
  };

  return {
    project,
    rev,
    jekyll,
    styles,
    scripts,
    images,
    fonts
  };
})();
