import { describe, expect, it } from 'vitest';
import { mkdir, mkdtemp, readFile, stat, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runInit } from '../src/server/init.ts';
import { parseWellKnown, selectEncryptionKey } from '../src/server/keys.ts';

describe('runInit', () => {
  it('creates recipient config with 0o600 private key mode', async () => {
    const tempDir = await mkdtemp(join(tmpdir(), 'koschei-init-'));
    const distDir = await mkdtemp(join(tmpdir(), 'koschei-dist-'));
    const outDir = join(tempDir, 'public');
    const privateKeyPath = join(tempDir, 'private.jwk');

    // Create fake dist files
    await mkdir(distDir, { recursive: true });
    await (await import('node:fs/promises')).writeFile(join(distDir, 'frame.html'), '<html></html>');
    await (await import('node:fs/promises')).writeFile(join(distDir, 'frame.js'), 'console.log("frame");');

    const written = await runInit({
      outDir,
      privateKeyPath,
      kid: 'test-2026-09',
      frameAncestors: 'https://example.com',
      distDir,
    });

    // Verify all 5 paths were written
    expect(written).toHaveLength(5);

    // Verify private key exists and has 0o600 mode
    const privateKeyStat = await stat(privateKeyPath);
    expect(privateKeyStat.mode & 0o777).toBe(0o600);

    // Verify well-known file exists and is valid JSON
    const wellKnownPath = join(outDir, '.well-known', 'sealed-input');
    const wellKnownContent = JSON.parse(await readFile(wellKnownPath, 'utf-8'));
    const doc = parseWellKnown(wellKnownContent);
    expect(doc.frame).toBe('/sealed-input/frame.html');

    // Verify selectEncryptionKey returns the correct kid
    const key = selectEncryptionKey(doc);
    expect(key.kid).toBe('test-2026-09');

    // Verify frame files were copied
    const frameHtmlPath = join(outDir, 'sealed-input', 'frame.html');
    const frameJsPath = join(outDir, 'sealed-input', 'frame.js');
    const htmlContent = await readFile(frameHtmlPath, 'utf-8');
    const jsContent = await readFile(frameJsPath, 'utf-8');
    expect(htmlContent).toBe('<html></html>');
    expect(jsContent).toBe('console.log("frame");');
  });

  it('refuses to overwrite existing private key without --force', async () => {
    const tempDir = await mkdtemp(join(tmpdir(), 'koschei-init-'));
    const distDir = await mkdtemp(join(tmpdir(), 'koschei-dist-'));
    const outDir = join(tempDir, 'public');
    const privateKeyPath = join(tempDir, 'private.jwk');

    // Create fake dist files
    await mkdir(distDir, { recursive: true });
    await (await import('node:fs/promises')).writeFile(join(distDir, 'frame.html'), '<html></html>');
    await (await import('node:fs/promises')).writeFile(join(distDir, 'frame.js'), 'console.log("frame");');

    // First run
    await runInit({
      outDir,
      privateKeyPath,
      kid: 'test-2026-09',
      frameAncestors: 'https://example.com',
      distDir,
    });

    // Second run without force should throw
    const outDir2 = join(tempDir, 'public2');
    await expect(
      runInit({
        outDir: outDir2,
        privateKeyPath,
        kid: 'test-2026-10',
        frameAncestors: 'https://example.com',
        distDir,
      }),
    ).rejects.toThrow(/already exists/);
  });

  it('overwrites existing private key with --force and enforces 0o600', async () => {
    const tempDir = await mkdtemp(join(tmpdir(), 'koschei-init-'));
    const distDir = await mkdtemp(join(tmpdir(), 'koschei-dist-'));
    const outDir = join(tempDir, 'public');
    const privateKeyPath = join(tempDir, 'private.jwk');

    // Create fake dist files
    await mkdir(distDir, { recursive: true });
    await (await import('node:fs/promises')).writeFile(join(distDir, 'frame.html'), '<html></html>');
    await (await import('node:fs/promises')).writeFile(join(distDir, 'frame.js'), 'console.log("frame");');

    // First run
    await runInit({
      outDir,
      privateKeyPath,
      kid: 'test-2026-09',
      frameAncestors: 'https://example.com',
      distDir,
    });

    // Change permissions to something broader
    await chmod(privateKeyPath, 0o644);
    const beforeStat = await stat(privateKeyPath);
    expect(beforeStat.mode & 0o777).toBe(0o644);

    // Second run with force should succeed and fix permissions
    const outDir2 = join(tempDir, 'public2');
    const written = await runInit({
      outDir: outDir2,
      privateKeyPath,
      kid: 'test-2026-10',
      frameAncestors: 'https://example.com',
      distDir,
      force: true,
    });

    // Verify private key file is in the written paths
    expect(written).toContain(privateKeyPath);

    // Verify permissions are back to 0o600
    const afterStat = await stat(privateKeyPath);
    expect(afterStat.mode & 0o777).toBe(0o600);

    // Verify the well-known doc has the new kid
    const outDir2WellKnown = join(outDir2, '.well-known', 'sealed-input');
    const wellKnownContent = JSON.parse(await readFile(outDir2WellKnown, 'utf-8'));
    const doc = parseWellKnown(wellKnownContent);
    const key = selectEncryptionKey(doc);
    expect(key.kid).toBe('test-2026-10');
  });
});
