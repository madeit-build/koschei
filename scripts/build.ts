import { build } from 'esbuild';
import { copyFile, mkdir, access } from 'node:fs/promises';

const entries: Array<{ entry: string; out: string }> = [
  { entry: 'src/frame/frame.ts', out: 'dist/frame.js' },
  { entry: 'src/element/sealed-input.ts', out: 'dist/sealed-input.js' },
];

await mkdir('dist', { recursive: true });
for (const { entry, out } of entries) {
  try {
    await access(entry);
  } catch {
    process.stderr.write(`skip ${entry} (not present yet)\n`);
    continue;
  }
  await build({ entryPoints: [entry], outfile: out, bundle: true, format: 'esm', target: 'es2022', sourcemap: true, minify: false });
  process.stdout.write(`built ${out}\n`);
}
await copyFile('src/frame/frame.html', 'dist/frame.html');
process.stdout.write('copied dist/frame.html\n');
