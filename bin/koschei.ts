#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { runInit } from '../src/server/init.ts';

const [command, ...rest] = process.argv.slice(2);

function usage(): never {
  process.stderr.write(
    [
      'usage:',
      '  koschei init   [--out public] [--private ./koschei-private.jwk] [--kid <kid>] [--frame-ancestors <origin>] [--dist dist] [--force]',
      '  koschei doctor <action-url> [--private ./koschei-private.jwk] [--page <embedding-origin>]',
      '',
    ].join('\n'),
  );
  process.exit(2);
}

if (command === 'init') {
  const { values } = parseArgs({
    args: rest,
    options: {
      out: { type: 'string', default: 'public' },
      private: { type: 'string', default: './koschei-private.jwk' },
      kid: { type: 'string', default: new Date().toISOString().slice(0, 7) },
      'frame-ancestors': { type: 'string', default: 'https://www.example.com' },
      dist: { type: 'string', default: 'dist' },
      force: { type: 'boolean', default: false },
    },
  });
  const written = await runInit({
    outDir: values.out,
    privateKeyPath: values.private,
    kid: values.kid,
    frameAncestors: values['frame-ancestors'],
    distDir: values.dist,
    force: values.force,
  });
  for (const path of written) process.stdout.write(`wrote ${path}\n`);
  process.stdout.write(`\nKeep ${values.private} out of the browser and out of git.\n`);
} else if (command === 'doctor') {
  const { runDoctorCli } = await import('../src/server/doctor.ts');
  process.exit(await runDoctorCli(rest));
} else {
  usage();
}
