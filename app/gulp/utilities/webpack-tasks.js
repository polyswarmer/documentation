module.exports = (plugins, entries, providePlugins, UglifyJsPlugin, lazypipe, isProduction) => {
  const webpackPlugins = [];

  if (providePlugins !== false) {
    webpackPlugins.push(new plugins.webpackStream.webpack.ProvidePlugin(providePlugins));
  }

  if (isProduction) {
    webpackPlugins.push(new UglifyJsPlugin());
  }

  return lazypipe().pipe(
    plugins.webpackStream,
    {
      entry: entries,
      output: {
        filename: '[name].js'
      },
      module: {
        rules: [
          {
            test: /\.js$/,
            loader: 'babel-loader',
            query: {
              presets: [
                [
                  'env',
                  {
                    targets: {
                      browsers: 'last 2 versions'
                    },
                    loose: true,
                    modules: false
                  }
                ]
              ],
              cacheDirectory: true,
              compact: isProduction
            }
          }
        ]
      },
      devtool: isProduction ? false : 'cheap-eval-source-map',
      plugins: webpackPlugins
    }
  )();
};
