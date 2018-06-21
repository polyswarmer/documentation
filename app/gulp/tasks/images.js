module.exports = (gulp, plugins, config, runSequence) => {
  gulp.task('images', () =>
    gulp
      .src(config.images.src + config.images.pattern)
      .pipe(plugins.newer(config.images.dest))
      .pipe(plugins.imagemin())
      .pipe(gulp.dest(config.images.dest))
  );

  gulp.task('images-watch', cb => {
    runSequence('images', 'reload', cb);
  });
};
