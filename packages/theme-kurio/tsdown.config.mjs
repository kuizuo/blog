export default {
  entry: ['src/index.ts', 'src/utils.ts'],
  outDir: 'lib',
  format: 'cjs',
  dts: false,
  unbundle: true,
  clean: true,
  fixedExtension: false,
  tsconfig: 'tsconfig.tsdown.json',
  copy: [{ from: 'src/theme', to: 'lib' }],
};
