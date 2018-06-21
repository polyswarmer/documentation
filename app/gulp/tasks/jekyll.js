module.exports = (gulp, config, exec, fs, replace, runSequence, jekyllRev, run, isProduction) => {
  // Asset versioning for Jekyll
  gulp.task('jekyll-rev', () => {
    if (isProduction) {
      fs.readFile(config.rev.manifest, 'utf8', (err, data) => {
        if (err) {
          throw err;
        }
        const manifest = JSON.parse(data);
        jekyllRev(manifest, config.jekyll.head, config.jekyll.foot, replace);
      });
    } else {
      const manifest = false;
      jekyllRev(manifest, config.jekyll.head, config.jekyll.foot, replace);
    }
  });

  // Build jekyll
  gulp.task('jekyll-build', cb => run(exec, 'bash -c "bundle exec jekyll build"', () => cb()));

  // Copy jekyll files into dist dir
  gulp.task('jekyll-copy', () =>
    gulp.src([`${config.jekyll.dest}/**/*`, `${config.jekyll.dest}/**/.*`]).pipe(gulp.dest(config.project.dest))
  );

  // Copy new jekyll files into dist dir (for watcher)
  gulp.task('jekyll-watch', cb => {
    runSequence('jekyll-build', 'jekyll-copy', 'reload', cb);
  });

  // Run a full build of jekyll
  gulp.task('jekyll', cb => {
    runSequence('jekyll-rev', 'jekyll-build', 'jekyll-copy', cb);
  });
};
