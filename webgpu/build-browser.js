const esbuild = require('esbuild');
const fs = require('fs');
const path = require('path');

// Plugin to handle ?raw imports (inline file contents as string)
const rawPlugin = {
  name: 'raw',
  setup(build) {
    build.onResolve({ filter: /\?raw$/ }, (args) => {
      const filePath = path.resolve(path.dirname(args.importer), args.path.replace('?raw', ''));
      return {
        path: filePath,
        namespace: 'raw-loader',
      };
    });

    build.onLoad({ filter: /.*/, namespace: 'raw-loader' }, async (args) => {
      const contents = await fs.promises.readFile(args.path, 'utf8');
      return {
        contents: `export default ${JSON.stringify(contents)};`,
        loader: 'js',
      };
    });
  },
};

async function build() {
  try {
    await esbuild.build({
      entryPoints: ['src/browser-benchmark.ts'],
      bundle: true,
      outfile: 'dist/browser-benchmark.js',
      format: 'iife',
      target: ['chrome113', 'firefox114', 'safari17'],
      minify: false,
      sourcemap: true,
      plugins: [rawPlugin],
    });
    console.log('Browser bundle built successfully: dist/browser-benchmark.js');
  } catch (error) {
    console.error('Build failed:', error);
    process.exit(1);
  }
}

build();
