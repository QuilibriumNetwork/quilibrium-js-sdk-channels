import typescript from '@rollup/plugin-typescript';
import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import wasm from '@rollup/plugin-wasm';
import dts from 'rollup-plugin-dts';
import postcss from 'rollup-plugin-postcss';

export default [
  {
    input: 'src/index.ts',
    output: [
      {
        file: 'dist/index.js',
        format: 'cjs',
      },
      {
        file: 'dist/index.esm.js',
        format: 'esm',
      },
    ],
    external: ['react', 'react-dom'],
    plugins: [
      postcss({
        extract: true,
        minimize: true,
      }),
      typescript(),
      resolve(),
      commonjs(),
      wasm({
        targetEnv: 'auto',
        publicPath: '/wasm/'
      })
    ]
  },
  {
    input: 'src/index.ts',
    output: [{ file: 'dist/index.d.ts', format: 'es' }],
    plugins: [
      postcss({
        extract: false,
        inject: false,
        modules: false
      }),
      dts()
    ]
  }
];
