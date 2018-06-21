module.exports = (gulp, browserSync) => {
  gulp.task('reload', cb => {
    browserSync.reload();
    cb();
  });
};
