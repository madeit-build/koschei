import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { DEFAULT_FRAME_PATH, generateRecipientKey, wellKnownDocument } from './keys.ts';

export interface InitOptions {
  outDir: string;
  privateKeyPath: string;
  kid: string;
  frameAncestors: string;
  distDir: string;
}

export async function runInit(options: InitOptions): Promise<string[]> {
  const pair = await generateRecipientKey(options.kid);
  const written: string[] = [];

  await writeFile(options.privateKeyPath, JSON.stringify(pair.privateJwk, null, 2) + '\n', { mode: 0o600 });
  written.push(options.privateKeyPath);

  const wellKnownPath = join(options.outDir, '.well-known', 'sealed-input');
  await mkdir(join(options.outDir, '.well-known'), { recursive: true });
  await writeFile(wellKnownPath, JSON.stringify(wellKnownDocument([pair.publicJwk]), null, 2) + '\n');
  written.push(wellKnownPath);

  const frameDir = join(options.outDir, 'sealed-input');
  await mkdir(frameDir, { recursive: true });
  for (const asset of ['frame.html', 'frame.js']) {
    const target = join(frameDir, asset);
    await writeFile(target, await readFile(join(options.distDir, asset)));
    written.push(target);
  }

  const headersPath = join(frameDir, 'HEADERS.txt');
  await writeFile(
    headersPath,
    [
      `# Send these response headers with ${DEFAULT_FRAME_PATH}:`,
      `Content-Security-Policy: frame-ancestors ${options.frameAncestors}`,
      '',
      '# Send this with /.well-known/sealed-input:',
      'Content-Type: application/json',
      `Access-Control-Allow-Origin: ${options.frameAncestors}`,
      '',
    ].join('\n'),
  );
  written.push(headersPath);
  return written;
}
