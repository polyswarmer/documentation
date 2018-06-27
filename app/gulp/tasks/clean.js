module.exports = (gulp, config, del) => {
  gulp.task('clean', () => del.sync(config.project.dest));
};
