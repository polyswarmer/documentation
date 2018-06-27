module.exports = (manifest, head, foot, replace) => {
  replace({
    regex: /-[a-zA-Z0-9]+\.js/g,
    replacement: '.js',
    paths: foot,
    recursive: true,
    silent: true
  });
  replace({
    regex: /-[a-zA-Z0-9]+\.css/g,
    replacement: '.css',
    paths: head,
    recursive: true,
    silent: true
  });

  if (manifest) {
    for (const entry in manifest) {
      if (manifest.hasOwnProperty(entry)) {
        const js = /\.js/.test(entry);
        const css = /\.css/.test(entry);
        const replacement = {
          regex: entry,
          replacement: manifest[entry],
          recursive: true,
          silent: true
        };
        if (js) {
          replacement.paths = foot;
        } else if (css) {
          replacement.paths = head;
        }
        replace(replacement);
      }
    }
  }
};
