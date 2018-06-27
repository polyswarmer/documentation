module.exports = (
  gulp,
  plugins,
  config,
  browserSync,
  runSequence,
  webpackTasks,
  UglifyJsPlugin,
  lazypipe,
  isProduction
) => {
  gulp.task('scripts-lint', () =>
    gulp
      .src(config.scripts.src + config.scripts.pattern)
      .pipe(plugins.eslint())
      .pipe(plugins.eslint.format())
      .pipe(plugins.eslint.failAfterError())
  );

  gulp.task('vendor-scripts', () =>
    gulp
      .src(config.scripts.src + config.scripts.pattern)
      .pipe(webpackTasks(plugins, config.scripts.vendorEntries, false, UglifyJsPlugin, lazypipe, isProduction))
      .pipe(plugins.if(isProduction, plugins.rev()))
      .pipe(gulp.dest(config.scripts.dest))
      .pipe(
        plugins.rev.manifest(config.rev.manifest, {
          base: config.project.dest,
          merge: true
        })
      )
      .pipe(gulp.dest(config.project.dest))
  );

  gulp.task('main-scripts', () =>
    gulp
      .src(config.scripts.src + config.scripts.pattern)
      .pipe(
        webpackTasks(
          plugins,
          config.scripts.mainEntries,
          config.scripts.providePlugins,
          UglifyJsPlugin,
          lazypipe,
          isProduction
        )
      )
      .pipe(gulp.dest(config.scripts.dest))
      .pipe(plugins.if(isProduction, plugins.rev()))
      .pipe(gulp.dest(config.scripts.dest))
      .pipe(browserSync.stream())
      .pipe(
        plugins.rev.manifest(config.rev.manifest, {
          base: config.project.dest,
          merge: true
        })
      )
      .pipe(gulp.dest(config.project.dest))
  );

  // Only compile main scripts (for watcher)
  gulp.task('scripts-watch', cb => {
    runSequence('scripts-lint', 'main-scripts', cb);
  });

  // Compile all scripts
  gulp.task('scripts', cb => {
    runSequence('scripts-lint', 'vendor-scripts', 'main-scripts', cb);
  });
};
