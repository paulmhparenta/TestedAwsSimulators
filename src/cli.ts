#!/usr/bin/env node
/**
 * Starts one or more simulators on their default ports.
 *
 *   npx tested-aws-simulators                 # all of them
 *   npx tested-aws-simulators s3 ses cognito  # only these
 *
 * Ports come from the *_PORT env vars named in each simulator (for example
 * S3_SIMULATOR_PORT). The Cognito emulator starts with the users in the JSON
 * file named by COGNITO_EMULATOR_USERS_FILE, or with one user
 * `user@example.com` / `Password1!` in the group `Users`.
 */
import fs from 'node:fs';

import { startS3Simulator } from './s3/s3-simulator';
import { startSesSimulator } from './ses/ses-simulator';
import { startCognitoEmulator, type CognitoSeedUser } from './cognito/cognito-emulator';
import { startSentrySimulator } from './sentry/sentry-simulator';
import { startOpenRouterSimulator } from './openrouter/openrouter-simulator';

const ALL = ['s3', 'ses', 'cognito', 'sentry', 'openrouter'] as const;
type Name = (typeof ALL)[number];

function readCognitoUsers(): CognitoSeedUser[] {
  const file = process.env.COGNITO_EMULATOR_USERS_FILE;
  if (file) {
    return JSON.parse(fs.readFileSync(file, 'utf8')) as CognitoSeedUser[];
  }
  return [{ userId: 'local-user-001', email: 'user@example.com', name: 'Local User', groups: ['Users'] }];
}

const starters: Record<Name, () => Promise<unknown>> = {
  s3: () => startS3Simulator(),
  ses: () => startSesSimulator(),
  cognito: () => startCognitoEmulator({
    users: readCognitoUsers(),
    clientId: process.env.COGNITO_EMULATOR_CLIENT_ID,
    issuer: process.env.COGNITO_EMULATOR_ISSUER,
    defaultRedirectUri: process.env.COGNITO_EMULATOR_REDIRECT_URI,
  }),
  sentry: () => startSentrySimulator(),
  openrouter: () => startOpenRouterSimulator(),
};

async function main(): Promise<void> {
  const requested = process.argv.slice(2);
  const unknown = requested.filter((name) => !(ALL as readonly string[]).includes(name));
  if (unknown.length > 0) {
    console.error(`Unknown simulator(s): ${unknown.join(', ')}. Choose from: ${ALL.join(', ')}.`);
    process.exit(2);
  }
  const names = (requested.length > 0 ? requested : ALL) as readonly Name[];
  for (const name of names) {
    await starters[name]();
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
