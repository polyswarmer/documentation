module.exports = (gulp, plugins, config, runSequence) => {
  gulp.task('fonts', () =>
    gulp
      .src(config.fonts.src + config.fonts.pattern)
      .pipe(plugins.newer(config.fonts.dest))
      .pipe(plugins.flatten())
      .pipe(gulp.dest(config.fonts.dest))
  );

  gulp.task('fonts-watch', cb => {
    runSequence('fonts', 'reload', cb);
  });
};
