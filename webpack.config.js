const path = require('path');

module.exports = {
  mode: process.env.NODE_ENV === 'production' ? 'production' : 'development',
  entry: {
    'backend/index': './src/backend/index.ts',
    'frontend/index': './src/frontend/index.tsx'
  },
  module: {
    rules: [
      {
        test: /\.(ts|tsx)$/,
        use: {
          loader: 'ts-loader',
          options: {
            transpileOnly: true,
            configFile: path.resolve(__dirname, 'tsconfig.json')
          }
        },
        exclude: /node_modules/,
      },
      {
        test: /\.css$/,
        use: ['style-loader', 'css-loader']
      }
    ],
  },
  resolve: {
    extensions: ['.tsx', '.ts', '.js', '.jsx'],
    alias: {
      '@': path.resolve(__dirname, 'src')
    }
  },
  output: {
    filename: '[name].js',
    path: path.resolve(__dirname, 'dist'),
    library: {
      type: 'commonjs2',
    },
    clean: true
  },
  target: 'node',
  externals: {
    '@caido/sdk-backend': 'commonjs @caido/sdk-backend',
    '@caido/sdk-frontend': 'commonjs @caido/sdk-frontend',
    'react': 'commonjs react',
    'react-dom': 'commonjs react-dom'
  },
  devtool: process.env.NODE_ENV === 'production' ? 'source-map' : 'eval-source-map',
  optimization: {
    minimize: process.env.NODE_ENV === 'production'
  }
};