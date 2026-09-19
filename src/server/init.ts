import { chmod, mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { DEFAULT_FRAME_PATH, generateRecipientKey, wellKnownDocument } from './keys.ts';

export interface InitOptions {
  outDir: string;
  privateKeyPath: string;
  kid: string;
  frameAncestors: string;
  distDir: string;
  force?: boolean;
}

const FRAME_ASSETS = ['frame.html', 'frame.js'] as const;

async function exists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw error;
  }
}

// Every precondition is checked before anything is written, so a failed run
// leaves no private key behind and never needs --force to retry.
export async function runInit(options: InitOptions): Promise<string[]> {
  if ((await exists(options.privateKeyPath)) && !options.force) {
    throw new Error(`${options.privateKeyPath} already exists; pass --force to overwrite it`);
  }
  for (const asset of FRAME_ASSETS) {
    const source = join(options.distDir, asset);
    if (!(await exists(source))) throw new Error(`${source} not found; run \`npm run build\` first`);
  }

  const pair = await generateRecipientKey(options.kid);
  const written: string[] = [];

  await writeFile(options.privateKeyPath, JSON.stringify(pair.privateJwk, null, 2) + '\n', { mode: 0o600 });
  await chmod(options.privateKeyPath, 0o600);
  written.push(options.privateKeyPath);

  const wellKnownPath = join(options.outDir, '.well-known', 'sealed-input');
  await mkdir(join(options.outDir, '.well-known'), { recursive: true });
  await writeFile(wellKnownPath, JSON.stringify(wellKnownDocument([pair.publicJwk]), null, 2) + '\n');
  written.push(wellKnownPath);

  const frameDir = join(options.outDir, 'sealed-input');
  await mkdir(frameDir, { recursive: true });
  for (const asset of FRAME_ASSETS) {
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
