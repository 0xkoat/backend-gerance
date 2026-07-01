const { RunScriptWebpackPlugin } = require('run-script-webpack-plugin');
const nodeExternals = require('webpack-node-externals');

module.exports = function (options, webpack) {
  let entry = options.entry;
  if (typeof entry === 'string') {
    entry = ['webpack/hot/poll?100', entry];
  } else if (Array.isArray(entry)) {
    entry = ['webpack/hot/poll?100', ...entry];
  } else if (typeof entry === 'object' && entry !== null) {
    entry = Object.keys(entry).reduce((acc, key) => {
      const val = entry[key];
      acc[key] = ['webpack/hot/poll?100', ...(Array.isArray(val) ? val : [val])];
      return acc;
    }, {});
  }

  return {
    ...options,
    entry,
    externals: [
      nodeExternals({
        allowlist: ['webpack/hot/poll?100'],
      }),
    ],
    plugins: [
      ...options.plugins,
      new webpack.WatchIgnorePlugin({
        paths: [/\.js$/, /\.d\.ts$/],
      }),
      new webpack.HotModuleReplacementPlugin(),
      new RunScriptWebpackPlugin({
        name: options.output.filename,
        autoRestart: false,
      }),
    ],
  };
};
