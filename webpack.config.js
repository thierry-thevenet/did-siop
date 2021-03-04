const webpack = require("webpack");
const path = require("path");

let config = {
   mode: 'development',
    entry: "./src/index.js",
    output: {
      path: path.resolve(__dirname, "/home/thierry/oidc_did/static"),
      filename: "./oidc-talao.min.js"
    },

}
  module.exports = config;
