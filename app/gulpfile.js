const argv = require('minimist')(process.argv.slice(2));
const browserSync = require('browser-sync').create();
const config = require('./gulp/config');
const del = require('del');
const exec = require('child_process').exec;
const fs = require('fs');
const gulp = require('gulp');
const jekyllRev = require('./gulp/utilities/jekyll-rev');
const lazypipe = require('lazypipe');
const replace = require('replace');
const run = require('./gulp/utilities/run');
const runSequence = require('run-sequence');
const UglifyJsPlugin = require('uglifyjs-webpack-plugin');
const webpackTasks = require('./gulp/utilities/webpack-tasks');

// Plugins
const plugins = require('gulp-load-plugins')({
  overridePattern: false,
  camelize: true,
  pattern: ['webpack*', 'gulp-*', 'gulp.*']
});

// Flags
const isProduction = argv.production;
const isAllLangs = argv['all-langs'];

// Gulp tasks
require('./gulp/tasks/clean')(gulp, config, del);
require('./gulp/tasks/reload')(gulp, browserSync);
require('./gulp/tasks/jekyll')(gulp, config, exec, fs, replace, runSequence, jekyllRev, run, isProduction, isAllLangs);
require('./gulp/tasks/styles')(gulp, plugins, config, browserSync, isProduction);
require('./gulp/tasks/scripts')(
  gulp,
  plugins,
  config,
  browserSync,
  runSequence,
  webpackTasks,
  UglifyJsPlugin,
  lazypipe,
  isProduction
);
require('./gulp/tasks/images')(gulp, plugins, config, runSequence);
require('./gulp/tasks/fonts')(gulp, plugins, config, runSequence);

gulp.task('watch', () => {
  browserSync.init({
    server: {
      baseDir: config.project.dest
    },
    open: false,
    online: false
  });
  plugins.watch(config.jekyll.watchFiles, () => gulp.start('jekyll-watch'));
  plugins.watch(config.styles.src + config.styles.pattern, () => gulp.start('styles'));
  plugins.watch(config.scripts.src + config.scripts.pattern, () => gulp.start('scripts-watch'));
  plugins.watch(config.images.src + config.images.pattern, () => gulp.start('images-watch'));
  plugins.watch(config.fonts.src + config.fonts.pattern, () => gulp.start('fonts-watch'));
});

gulp.task('default', cb => {
  runSequence('clean', 'styles', ['scripts', 'images', 'fonts'], 'jekyll', cb);
});
