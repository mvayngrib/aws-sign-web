const path = require('path')
const webpack = require('webpack')
const debug = process.env.NODE_ENV !== "production"
const outputPath = path.resolve(__dirname, "build")

module.exports = {
  context: __dirname,
  devtool: debug ? "inline-sourcemap" : null,
  entry: './example.js',
  output: './bundle.js',
  plugins: debug ? [] : [
    new webpack.optimize.DedupePlugin(),
    new webpack.optimize.OccurenceOrderPlugin(),
    new webpack.optimize.UglifyJsPlugin({ mangle: false, sourcemap: false }),
  ],
}
