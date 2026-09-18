/**
 * Cognito user pool emulator for local development and tests.
 *
 * Two surfaces, on one port:
 *
 * 1. The hosted-UI OAuth endpoints a browser app uses:
 *      GET  /oauth2/authorize            – user picker page, then a code redirect (PKCE S256 only)
 *      POST /oauth2/token                – authorization_code grant
 *      GET  /.well-known/jwks.json       – RS256 public key
 *      GET  /.well-known/openid-configuration
 *      GET  /logout
 *
 * 2. The Cognito Identity Provider JSON API (`x-amz-target:
 *    AWSCognitoIdentityProviderService.<Action>`) that
 *    `@aws-sdk/client-cognito-identity-provider` sends:
 *      InitiateAuth (USER_PASSWORD_AUTH, REFRESH_TOKEN_AUTH), ListUsers,
 *      AdminGetUser, AdminCreateUser, AdminUpdateUserAttributes,
 *      AdminSetUserPassword, AdminDeleteUser, AdminListGroupsForUser,
 *      AdminAddUserToGroup, AdminRemoveUserFromGroup, AdminUserGlobalSignOut,
 *      ForgotPassword, ConfirmForgotPassword, GetUser, AssociateSoftwareToken,
 *      VerifySoftwareToken, SetUserMFAPreference
 *
 * Tokens are RS256 JWTs signed with a key generated at start-up, so a verifier
 * pointed at `/.well-known/jwks.json` accepts them exactly as it accepts real
 * Cognito tokens.
 *
 * FIDELITY RULE. Every refusal below is one real Cognito makes, with the same
 * `__type` and message. An emulator that accepts what Cognito refuses makes a
 * test suite green on a path that fails in production, so where the two
 * differ, the emulator is wrong.
 *
 * Test hooks (HTTP):
 *   GET  /__local/forgot-password-code?email=…       – the code ForgotPassword issued
 *   POST /__local/expire-forgot-password-code?email=… – move that code's expiry into the past
 *   GET  /__local/mfa-state?email=…                   – { enabled } for software-token MFA
 *   POST /__local/reset                               – reset to the seed users, drop all codes and tokens
 */

import express, { type Response as ExpressResponse } from 'express';
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  createSign,
  generateKeyPairSync,
  randomBytes,
  randomInt,
  randomUUID,
} from 'node:crypto';

import { escapeHtml, listen, type RunningSimulator } from '../shared/server';

export const COGNITO_EMULATOR_DEFAULT_PORT = 38303;
export const COGNITO_EMULATOR_DEFAULT_CLIENT_ID = 'local-web-client';
export const COGNITO_EMULATOR_DEFAULT_PASSWORD = 'Password1!';

/**
 * The scope Cognito requires for a call a user makes about their own account
 * — GetUser and the three TOTP calls below.
 */
export const COGNITO_SELF_SERVICE_SCOPE = 'aws.cognito.signin.user.admin';

/**
 * The scope list the emulator issues when the caller names none. Keep it the
 * same as `allowed_oauth_scopes` on your real app client: a token minted here
 * with more scopes than Cognito grants hides a real refusal.
 */
export const COGNITO_EMULATOR_DEFAULT_SCOPE = `openid email profile ${COGNITO_SELF_SERVICE_SCOPE}`;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A user the emulator starts with. */
export interface CognitoSeedUser {
  /** The Cognito `sub` and `Username`. */
  readonly userId: string;
  readonly email: string;
  /** Display name, split into given_name / family_name on the way out. May be empty. */
  readonly name: string;
  /** Cognito groups. The FIRST entry is the user's primary group on the authorize page. */
  readonly groups: readonly string[];
  /** Default `Password1!`. */
  readonly password?: string;
  /** Cognito `email_verified`. Default true. */
  readonly emailVerified?: boolean;
  /**
   * `UserStatus === 'FORCE_CHANGE_PASSWORD'`: an account created by
   * AdminCreateUser that has never set its own password. Default false.
   */
  readonly forceChangePassword?: boolean;
  /**
   * Custom attributes WITHOUT the `custom:` prefix, e.g. `{ tenantId: 'a' }`.
   * They appear as `custom:tenantId` on the ID token, ListUsers and AdminGetUser.
   */
  readonly customAttributes?: Readonly<Record<string, string>>;
}

export interface CognitoEmulatorOptions {
  /** The users the pool starts with, and returns to on reset. */
  readonly users?: readonly CognitoSeedUser[];
  /** The one app client id the emulator accepts. Default `local-web-client`. */
  readonly clientId?: string;
  /**
   * The `iss` claim. Default: the origin the request arrived on, so a token
   * minted through `http://localhost:38303` names that issuer.
   */
  readonly issuer?: string;
  /** Used when /oauth2/authorize is called with no redirect_uri. */
  readonly defaultRedirectUri?: string;
  /** Access and ID token lifetime. Default 3600. */
  readonly tokenTtlSeconds?: number;
  /** Default `COGNITO_EMULATOR_DEFAULT_SCOPE`. */
  readonly defaultScope?: string;
  /** Groups an account created by AdminCreateUser starts in. Default none, as in Cognito. */
  readonly newUserGroups?: readonly string[];
}

/** A user as the emulator holds it. */
export interface CognitoUserRecord {
  readonly userId: string;
  readonly email: string;
  readonly name: string;
  readonly groups: readonly string[];
  readonly emailVerified: boolean;
  readonly forceChangePassword: boolean;
  readonly customAttributes: Readonly<Record<string, string>>;
  readonly softwareTokenMfaEnabled: boolean;
  readonly createdAt: string;
}

export interface CognitoEmulator {
  readonly app: express.Express;
  readonly clientId: string;
  /** The current users, in creation order. */
  listUsers(): readonly CognitoUserRecord[];
  getUser(userIdOrEmail: string): CognitoUserRecord | null;
  /** Resets to the seed users and drops every code and refresh token. */
  reset(): void;
}

interface MutableUser {
  userId: string;
  email: string;
  name: string;
  groups: string[];
  password: string;
  emailVerified: boolean;
  forceChangePassword: boolean;
  customAttributes: Record<string, string>;
  softwareTokenSecret?: string;
  softwareTokenMfaEnabled: boolean;
  createdAt: string;
}

/** The access-token claims this emulator reads back from a token it minted. */
interface AccessTokenClaims {
  readonly sub?: string;
  readonly token_use?: string;
  readonly scope?: string;
}

interface AuthorizationCodeRecord {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly codeChallenge: string;
  readonly scope: string;
  readonly userId: string;
  readonly issuer: string;
  readonly createdAtMs: number;
  readonly sessionId: string;
}

interface RefreshTokenRecord {
  readonly userId: string;
  readonly clientId: string;
  readonly scope: string;
  readonly sessionId: string;
  readonly issuer: string;
}

interface ForgotPasswordCodeRecord {
  code: string;
  /** Epoch ms after which `ConfirmForgotPassword` answers ExpiredCodeException. */
  expiresAtMs: number;
}

type JwtTokenClaims = Record<string, unknown>;

type CognitoAttribute = { Name: string; Value: string };

const AUTHORIZATION_CODE_TTL_MS = 5 * 60 * 1000;
const FORGOT_PASSWORD_CODE_TTL_MS = 60 * 60 * 1000;

/**
 * Attributes real Cognito allows in a `ListUsers` Filter expression. Custom
 * attributes are deliberately absent — Cognito rejects them.
 */
const COGNITO_FILTERABLE_ATTRIBUTES = new Set([
  'username',
  'email',
  'phone_number',
  'name',
  'given_name',
  'family_name',
  'preferred_username',
  'cognito:user_status',
  'status',
  'sub',
]);

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

function toBase64Url(input: Buffer | string): string {
  const bufferValue = typeof input === 'string' ? Buffer.from(input) : input;
  return bufferValue.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function createRandomValue(byteLength: number): string {
  return toBase64Url(randomBytes(byteLength));
}

function primaryGroup(user: { readonly groups: readonly string[] }): string {
  return user.groups[0] ?? '';
}

/** `wendy@example.org` -> `w***@e***.org`, the shape Cognito returns. */
export function maskEmailDestination(email: string): string {
  const at = email.indexOf('@');
  if (at <= 0) return '***';
  const domain = email.slice(at + 1);
  const lastDot = domain.lastIndexOf('.');
  const maskedDomain = lastDot <= 0
    ? `${domain.slice(0, 1)}***`
    : `${domain.slice(0, 1)}***${domain.slice(lastDot)}`;
  return `${email.slice(0, 1)}***@${maskedDomain}`;
}

/** The first rule of Cognito's default password policy that `password` breaks, or null. */
export function validateCognitoDefaultPasswordPolicy(password: string): string | null {
  if (password.length < 8) return 'Password must have length greater than or equal to 8';
  if (password.length > 256) return 'Password must have length less than or equal to 256';
  if (!/[A-Z]/.test(password)) return 'Password must have uppercase characters';
  if (!/[a-z]/.test(password)) return 'Password must have lowercase characters';
  if (!/[0-9]/.test(password)) return 'Password must have numeric characters';
  if (!/[\^$*.[\]{}()?\-"!@#%&/\\,><':;|_~`+=]/.test(password)) {
    return 'Password must have symbol characters';
  }
  return null;
}

function isValidEmailFormat(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function toEpochSeconds(isoTimestamp: string): number {
  const epochMs = Date.parse(isoTimestamp);
  return Number.isFinite(epochMs) ? Math.floor(epochMs / 1000) : 0;
}

function parseAwsJsonBody(rawBody: unknown): Record<string, unknown> {
  if (!rawBody || typeof rawBody !== 'object' || Array.isArray(rawBody)) {
    return {};
  }
  return rawBody as Record<string, unknown>;
}

function readAttributes(value: unknown): Array<{ Name?: string; Value?: string }> {
  return Array.isArray(value) ? (value as Array<{ Name?: string; Value?: string }>) : [];
}

function customAttributesFrom(attrs: Array<{ Name?: string; Value?: string }>): Record<string, string> {
  const custom: Record<string, string> = {};
  for (const attr of attrs) {
    if (attr.Name?.startsWith('custom:') && attr.Value !== undefined) {
      custom[attr.Name.slice('custom:'.length)] = attr.Value;
    }
  }
  return custom;
}

function toCognitoUserAttributes(user: MutableUser): CognitoAttribute[] {
  const nameParts = user.name.trim().split(/\s+/).filter(Boolean);
  const givenName = nameParts[0] ?? '';
  const familyName = nameParts.length > 1 ? nameParts.slice(1).join(' ') : '';

  const attributes: CognitoAttribute[] = [
    { Name: 'sub', Value: user.userId },
    { Name: 'email', Value: user.email },
    // Real Cognito serialises this as a string. Emitting a JSON boolean would
    // make the emulator disagree with production over the exact value.
    { Name: 'email_verified', Value: user.emailVerified ? 'true' : 'false' },
  ];

  // Real Cognito omits attributes that were never set, so a nameless (invited,
  // not yet activated) user comes back with no name attributes at all rather
  // than an empty given_name.
  if (givenName) attributes.push({ Name: 'given_name', Value: givenName });
  if (familyName) attributes.push({ Name: 'family_name', Value: familyName });

  // Cognito returns custom attributes on ListUsers and AdminGetUser, and a
  // caller that cannot filter on them server-side filters on them in memory.
  for (const [name, value] of Object.entries(user.customAttributes)) {
    attributes.push({ Name: `custom:${name}`, Value: value });
  }

  return attributes;
}

function userStatus(user: MutableUser): string {
  return user.forceChangePassword ? 'FORCE_CHANGE_PASSWORD' : 'CONFIRMED';
}

function toRecord(user: MutableUser): CognitoUserRecord {
  return {
    userId: user.userId,
    email: user.email,
    name: user.name,
    groups: [...user.groups],
    emailVerified: user.emailVerified,
    forceChangePassword: user.forceChangePassword,
    customAttributes: { ...user.customAttributes },
    softwareTokenMfaEnabled: user.softwareTokenMfaEnabled,
    createdAt: user.createdAt,
  };
}

function fromSeed(seed: CognitoSeedUser): MutableUser {
  return {
    userId: seed.userId,
    email: seed.email,
    name: seed.name,
    groups: [...seed.groups],
    password: seed.password ?? COGNITO_EMULATOR_DEFAULT_PASSWORD,
    emailVerified: seed.emailVerified ?? true,
    forceChangePassword: seed.forceChangePassword ?? false,
    customAttributes: { ...(seed.customAttributes ?? {}) },
    softwareTokenMfaEnabled: false,
    createdAt: new Date(0).toISOString(),
  };
}

/**
 * The claims of an ACCESS token, or undefined when the token is not one.
 *
 * Reads the payload without verifying the signature: this is a local emulator
 * and the token it is handed is one it minted.
 */
function readAccessTokenClaims(token: string): AccessTokenClaims | undefined {
  const parts = token.trim().split('.');
  if (parts.length < 2) return undefined;
  try {
    const claims = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8')) as AccessTokenClaims;
    return claims.token_use === 'access' ? claims : undefined;
  } catch {
    return undefined;
  }
}

function renderAuthorizePage(params: Record<string, string>, users: readonly MutableUser[]): string {
  const hidden = Object.entries(params)
    .map(([name, value]) => `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}" />`)
    .join('\n        ');

  const seenGroups = new Set<string>();
  const userButtons = users
    .map((user) => {
      const groupLower = primaryGroup(user).toLowerCase();
      // The first user per primary group gets `local-auth-continue-<group>`,
      // so a test can pick "an Admin" without knowing an id. Every other user
      // gets `local-auth-continue-user-<userId>`.
      let testId: string;
      if (groupLower && !seenGroups.has(groupLower)) {
        seenGroups.add(groupLower);
        testId = `local-auth-continue-${groupLower}`;
      } else {
        testId = `local-auth-continue-user-${user.userId}`;
      }
      return `<button type="submit" name="selected_user" value="${escapeHtml(user.userId)}" data-testid="${escapeHtml(testId)}">
            <span class="btn-name">${escapeHtml(user.name || user.email)}</span>
            <span class="btn-meta">${escapeHtml(user.email)} &middot; ${escapeHtml(user.groups.join(', '))}</span>
          </button>`;
    })
    .join('\n          ');

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Local OAuth Simulator</title>
    <style>
      body { font-family: system-ui, Arial, sans-serif; margin: 0; background: #f8fafc; color: #0f172a; }
      .container { max-width: 560px; margin: 7rem auto; background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 2rem; box-shadow: 0 10px 25px rgba(15, 23, 42, 0.08); }
      h1 { margin: 0 0 0.75rem; font-size: 1.35rem; }
      p { margin: 0.5rem 0; line-height: 1.45; }
      .meta { margin-top: 1rem; padding: 0.75rem; background: #f1f5f9; border-radius: 8px; font-size: 0.9rem; }
      .actions { display: flex; flex-direction: column; gap: 0.75rem; margin-top: 1.25rem; }
      button { appearance: none; border: 1px solid #cbd5e1; border-radius: 8px; padding: 0.75rem 1rem; background: #fff; color: #0f172a; font-size: 0.95rem; cursor: pointer; text-align: left; display: flex; flex-direction: column; gap: 0.2rem; }
      button:hover { background: #f1f5f9; border-color: #2563eb; }
      .btn-name { font-weight: 600; }
      .btn-meta { font-size: 0.82rem; color: #64748b; }
    </style>
  </head>
  <body>
    <main class="container">
      <h1>Local OAuth Simulator</h1>
      <p>This is where the Cognito Hosted UI login would happen.</p>
      <p>Select a user to sign in as:</p>
      <div class="meta">
        <div><strong>Client:</strong> ${escapeHtml(params.client_id ?? '')}</div>
        <div><strong>Redirect:</strong> ${escapeHtml(params.redirect_uri ?? '')}</div>
      </div>
      <form method="get" action="/oauth2/authorize">
        ${hidden}
        <input type="hidden" name="continue" value="1" />
        <div class="actions">
          ${userButtons || '<p><em>No users are configured.</em></p>'}
        </div>
      </form>
    </main>
  </body>
</html>`;
}

// ---------------------------------------------------------------------------
// Emulator factory
// ---------------------------------------------------------------------------

export function createCognitoEmulator(options: CognitoEmulatorOptions = {}): CognitoEmulator {
  const clientId = options.clientId ?? COGNITO_EMULATOR_DEFAULT_CLIENT_ID;
  const tokenTtlSeconds = options.tokenTtlSeconds ?? 3600;
  const defaultScope = options.defaultScope ?? COGNITO_EMULATOR_DEFAULT_SCOPE;
  const seedUsers = options.users ?? [];

  /** The one user directory. Admin calls and token minting both read it. */
  const users: MutableUser[] = seedUsers.map(fromSeed);
  const authorizationCodes = new Map<string, AuthorizationCodeRecord>();
  const refreshTokensByValue = new Map<string, RefreshTokenRecord>();
  /**
   * Reset codes issued by `ForgotPassword`, keyed by user id. A second
   * `ForgotPassword` for the same user REPLACES the entry, matching Cognito:
   * only the newest code works.
   */
  const forgotPasswordCodesByUserId = new Map<string, ForgotPasswordCodeRecord>();

  const rsaKeyPair = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const privateKey = createPrivateKey(rsaKeyPair.privateKey.export({ format: 'pem', type: 'pkcs8' }));
  const publicKey = createPublicKey(rsaKeyPair.publicKey.export({ format: 'pem', type: 'spki' }));
  const jwkPublicKey = publicKey.export({ format: 'jwk' }) as Record<string, string>;
  const keyId = createHash('sha256').update(JSON.stringify(jwkPublicKey)).digest('hex').slice(0, 16);

  function issuerFor(req: express.Request): string {
    return (options.issuer ?? `${req.protocol}://${req.get('host') ?? 'localhost'}`).trim();
  }

  function findById(userId: string): MutableUser | undefined {
    return users.find((u) => u.userId === userId);
  }

  function findByLogin(login: string): MutableUser | undefined {
    const trimmed = login.trim().toLowerCase();
    if (!trimmed) return undefined;
    return users.find((u) => u.email.toLowerCase() === trimmed || u.userId.toLowerCase() === trimmed);
  }

  function resolveUserSelection(selected: string): MutableUser | undefined {
    const trimmed = selected.trim();
    const byUserId = findById(trimmed);
    if (byUserId) return byUserId;
    // Match the primary group (the first entry), which is the one the authorize
    // page advertises through its `local-auth-continue-<group>` testId.
    const byGroup = users.find((u) => primaryGroup(u).toLowerCase() === trimmed.toLowerCase());
    return byGroup ?? users[0];
  }

  function signJwt(claims: JwtTokenClaims): string {
    const header = { alg: 'RS256', typ: 'JWT', kid: keyId };
    const signingInput = `${toBase64Url(JSON.stringify(header))}.${toBase64Url(JSON.stringify(claims))}`;
    const signer = createSign('RSA-SHA256');
    signer.update(signingInput);
    signer.end();
    return `${signingInput}.${toBase64Url(signer.sign(privateKey))}`;
  }

  function createTokenClaims(
    tokenUse: 'id' | 'access',
    scope: string,
    user: MutableUser,
    tokenClientId: string,
    sessionId: string,
    issuer: string,
  ): JwtTokenClaims {
    const now = Math.floor(Date.now() / 1000);
    const baseClaims: JwtTokenClaims = {
      iss: issuer,
      version: 2,
      client_id: tokenClientId,
      origin_jti: sessionId,
      event_id: randomUUID(),
      exp: now + tokenTtlSeconds,
      iat: now,
      auth_time: now,
      jti: randomUUID(),
      sub: user.userId,
      token_use: tokenUse,
      scope,
    };

    if (tokenUse === 'access') {
      // Real Cognito puts NO `custom:*` user attributes on the access token —
      // they live on the ID token only. An emulator that carried them here
      // would let a caller that reads the wrong token resolve them locally
      // while the same call fails against real Cognito.
      return {
        ...baseClaims,
        username: user.userId,
        'cognito:groups': [...user.groups],
      };
    }

    const customClaims: Record<string, string> = {};
    for (const [name, value] of Object.entries(user.customAttributes)) {
      customClaims[`custom:${name}`] = value;
    }

    return {
      ...baseClaims,
      aud: tokenClientId,
      email: user.email,
      email_verified: user.emailVerified,
      'cognito:username': user.userId,
      'cognito:groups': [...user.groups],
      ...customClaims,
    };
  }

  function issueTokens(user: MutableUser, scope: string, tokenClientId: string, sessionId: string, issuer: string) {
    return {
      idToken: signJwt(createTokenClaims('id', scope, user, tokenClientId, sessionId, issuer)),
      accessToken: signJwt(createTokenClaims('access', scope, user, tokenClientId, sessionId, issuer)),
    };
  }

  function assertPkceS256(verifier: string, expectedChallenge: string): boolean {
    return toBase64Url(createHash('sha256').update(verifier).digest()) === expectedChallenge;
  }

  /**
   * The user a self-service Cognito call is for, or undefined once the refusal
   * has been written to `res`.
   *
   * WHY THE SCOPE IS CHECKED HERE. `GetUser`, `AssociateSoftwareToken`,
   * `VerifySoftwareToken` and `SetUserMFAPreference` are calls the browser
   * makes for its own account, and real Cognito refuses every one of them with
   * HTTP 400 "Access Token does not have required scopes" unless the access
   * token carries `aws.cognito.signin.user.admin`. An emulator that ignores
   * scopes lets a missing scope pass locally and fail in every deployed
   * environment.
   *
   * The two refusals are ordered as Cognito orders them: an unreadable or
   * unknown token is "Invalid Access Token", and only a token that names a
   * real user is then judged on its scopes.
   */
  function resolveSelfServiceUser(token: string, res: ExpressResponse): MutableUser | undefined {
    const claims = readAccessTokenClaims(token);
    const user = claims?.sub ? findById(claims.sub) : undefined;
    if (!claims || !user) {
      res.status(400).json({ __type: 'NotAuthorizedException', message: 'Invalid Access Token' });
      return undefined;
    }

    const grantedScopes = String(claims.scope ?? '').split(/\s+/).filter(Boolean);
    if (!grantedScopes.includes(COGNITO_SELF_SERVICE_SCOPE)) {
      res.status(400).json({
        __type: 'NotAuthorizedException',
        message: 'Access Token does not have required scopes',
      });
      return undefined;
    }

    return user;
  }

  function reset(): void {
    authorizationCodes.clear();
    refreshTokensByValue.clear();
    // A code left over from a previous test would let the next one confirm a
    // reset it never requested.
    forgotPasswordCodesByUserId.clear();
    users.length = 0;
    users.push(...seedUsers.map(fromSeed));
  }

  function findByEmailQuery(req: express.Request): MutableUser | undefined {
    const email = String(req.query.email ?? '').trim().toLowerCase();
    return users.find((u) => u.email.toLowerCase() === email);
  }

  const app = express();
  app.use(express.urlencoded({ extended: false }));
  // Match both standard JSON and the AWS JSON protocol content types. The SDK
  // sends `application/x-amz-json-1.1`, and without this the parsed body is
  // empty and every Admin* lookup silently returns an empty result.
  app.use(express.json({ type: ['application/json', 'application/x-amz-json-1.0', 'application/x-amz-json-1.1'] }));

  app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.header(
      'Access-Control-Allow-Headers',
      'Content-Type, Authorization, X-Amz-Target, X-Amz-User-Agent, X-Amz-Date, amz-sdk-invocation-id, amz-sdk-request',
    );
    if (req.method === 'OPTIONS') {
      res.sendStatus(204);
      return;
    }
    next();
  });

  // ---- Hosted UI --------------------------------------------------------------

  app.get('/oauth2/authorize', (req, res) => {
    const responseType = String(req.query.response_type ?? '').trim();
    const requestClientId = String(req.query.client_id ?? '').trim();
    const redirectUri = String(req.query.redirect_uri ?? '').trim() || (options.defaultRedirectUri ?? '');
    const state = String(req.query.state ?? '').trim();
    const scope = String(req.query.scope ?? defaultScope).trim();
    const codeChallenge = String(req.query.code_challenge ?? '').trim();
    const codeChallengeMethod = String(req.query.code_challenge_method ?? '').trim();

    if (responseType !== 'code') {
      res.redirect(302, `/error?error=invalid_request&error_description=${encodeURIComponent('response_type must be code')}`);
      return;
    }
    if (!requestClientId || requestClientId !== clientId) {
      res.redirect(302, `/error?error=invalid_request&error_description=${encodeURIComponent('Invalid client id.')}`);
      return;
    }
    if (!redirectUri) {
      res.status(400).json({ error: 'invalid_request', error_description: 'redirect_uri is required' });
      return;
    }
    if (!state) {
      res.status(400).json({ error: 'invalid_request', error_description: 'state is required' });
      return;
    }
    if (!codeChallenge || codeChallengeMethod !== 'S256') {
      res.status(400).json({ error: 'invalid_request', error_description: 'PKCE S256 is required' });
      return;
    }

    if (String(req.query.continue ?? '').trim() !== '1') {
      res.status(200).type('html').send(renderAuthorizePage({
        response_type: responseType,
        client_id: requestClientId,
        redirect_uri: redirectUri,
        state,
        scope,
        code_challenge: codeChallenge,
        code_challenge_method: codeChallengeMethod,
      }, users));
      return;
    }

    const selectedUser = resolveUserSelection(String(req.query.selected_user ?? ''));
    if (!selectedUser) {
      res.status(400).json({ error: 'invalid_request', error_description: 'The emulator has no users to sign in as.' });
      return;
    }

    const authorizationCode = createRandomValue(24);
    authorizationCodes.set(authorizationCode, {
      clientId: requestClientId,
      redirectUri,
      codeChallenge,
      scope,
      userId: selectedUser.userId,
      issuer: issuerFor(req),
      createdAtMs: Date.now(),
      sessionId: randomUUID(),
    });

    const redirectUrl = new URL(redirectUri);
    redirectUrl.searchParams.set('code', authorizationCode);
    redirectUrl.searchParams.set('state', state);
    res.redirect(302, redirectUrl.toString());
  });

  app.post('/oauth2/token', (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const grantType = String(body.grant_type ?? '').trim();
    const code = String(body.code ?? '').trim();
    const requestClientId = String(body.client_id ?? '').trim();
    const codeVerifier = String(body.code_verifier ?? '').trim();
    const redirectUri = String(body.redirect_uri ?? '').trim();

    if (grantType !== 'authorization_code') {
      res.status(400).json({ error: 'unsupported_grant_type' });
      return;
    }
    if (!code || !requestClientId || !codeVerifier || !redirectUri) {
      res.status(400).json({ error: 'invalid_request' });
      return;
    }
    if (requestClientId !== clientId) {
      res.status(401).json({ error: 'invalid_client' });
      return;
    }

    // Each `invalid_grant` says which of four different defects it is: an
    // unknown code, an expired one, a redirect mismatch or a PKCE mismatch.
    // The unknown-code case says how many codes are outstanding, because
    // "never issued" and "already redeemed" are the same branch and are told
    // apart by that count.
    const authRecord = authorizationCodes.get(code);
    if (!authRecord) {
      res.status(400).json({
        error: 'invalid_grant',
        error_description: `unknown or already-redeemed authorization code; ${authorizationCodes.size} code(s) outstanding on this emulator`,
      });
      return;
    }

    const ageMs = Date.now() - authRecord.createdAtMs;
    if (ageMs > AUTHORIZATION_CODE_TTL_MS) {
      authorizationCodes.delete(code);
      res.status(400).json({
        error: 'invalid_grant',
        error_description: `authorization code expired ${ageMs - AUTHORIZATION_CODE_TTL_MS} ms ago`,
      });
      return;
    }

    if (authRecord.redirectUri !== redirectUri || authRecord.clientId !== requestClientId) {
      res.status(400).json({
        error: 'invalid_grant',
        error_description: 'redirect_uri or client_id does not match the one the code was issued for',
      });
      return;
    }

    if (!assertPkceS256(codeVerifier, authRecord.codeChallenge)) {
      // A sign-in that starts twice and finishes with the second attempt's
      // verifier lands here.
      res.status(400).json({
        error: 'invalid_grant',
        error_description: 'PKCE verifier does not match the challenge the code was issued for',
      });
      return;
    }

    authorizationCodes.delete(code);

    const user = findById(authRecord.userId);
    if (!user) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'the user this code was issued for no longer exists' });
      return;
    }

    const { idToken, accessToken } = issueTokens(user, authRecord.scope, authRecord.clientId, authRecord.sessionId, authRecord.issuer);
    const refreshToken = createRandomValue(32);
    refreshTokensByValue.set(refreshToken, {
      userId: user.userId,
      clientId: authRecord.clientId,
      scope: authRecord.scope,
      sessionId: authRecord.sessionId,
      issuer: authRecord.issuer,
    });

    res.json({
      token_type: 'Bearer',
      expires_in: tokenTtlSeconds,
      id_token: idToken,
      access_token: accessToken,
      refresh_token: refreshToken,
    });
  });

  app.get('/.well-known/jwks.json', (_req, res) => {
    res.json({ keys: [{ ...jwkPublicKey, alg: 'RS256', use: 'sig', kid: keyId }] });
  });

  app.get('/.well-known/openid-configuration', (req, res) => {
    const issuer = issuerFor(req);
    res.json({
      issuer,
      authorization_endpoint: `${issuer}/oauth2/authorize`,
      token_endpoint: `${issuer}/oauth2/token`,
      jwks_uri: `${issuer}/.well-known/jwks.json`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none'],
      scopes_supported: ['openid', 'email', 'profile', COGNITO_SELF_SERVICE_SCOPE],
    });
  });

  app.get('/logout', (req, res) => {
    const logoutUri = String(req.query.logout_uri ?? '').trim();
    if (logoutUri) {
      res.redirect(302, logoutUri);
      return;
    }
    res.status(400).type('html').send(`<!doctype html>
<html lang="en">
  <head><meta charset="utf-8" /><title>Logged Out</title></head>
  <body><p>Logged out. No logout_uri provided.</p></body>
</html>`);
  });

  app.get('/error', (req, res) => {
    const errorCode = String(req.query.error ?? '').trim() || 'invalid_request';
    const errorDescription = String(req.query.error_description ?? '').trim()
      || 'An error was encountered with the requested page.';
    res.status(400).type('html').send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Cognito Error</title>
    <style>body{font-family:system-ui,Arial,sans-serif;margin:2rem;color:#111}h1{font-size:1.25rem}code{background:#f3f4f6;padding:.15rem .35rem;border-radius:4px}</style>
  </head>
  <body>
    <h1>An error was encountered with the requested page.</h1>
    <p><code>${escapeHtml(errorCode)}</code></p>
    <p>${escapeHtml(errorDescription)}</p>
  </body>
</html>`);
  });

  // ---- Test hooks -------------------------------------------------------------

  /**
   * The MFA state a test asserts. An enrolment test must read the RESULTING
   * state, not that a QR code rendered — the second passes while enrolment
   * silently fails.
   */
  app.get('/__local/mfa-state', (req, res) => {
    res.json({ enabled: findByEmailQuery(req)?.softwareTokenMfaEnabled === true });
  });

  /**
   * The reset code `ForgotPassword` just issued, or null. Real Cognito emails
   * it; a test reads the code the product actually caused to be issued, so the
   * confirm step runs with the real value rather than a fixture.
   */
  app.get('/__local/forgot-password-code', (req, res) => {
    const user = findByEmailQuery(req);
    const record = user ? forgotPasswordCodesByUserId.get(user.userId) : undefined;
    res.json({ code: record?.code ?? null });
  });

  /** Moves the stored code's expiry into the past, so the expired branch runs without waiting an hour. */
  app.post('/__local/expire-forgot-password-code', (req, res) => {
    const user = findByEmailQuery(req);
    const record = user ? forgotPasswordCodesByUserId.get(user.userId) : undefined;
    if (!record) {
      res.status(404).json({ error: 'No forgot-password code for that address.' });
      return;
    }
    record.expiresAtMs = Date.now() - 1000;
    res.json({ expired: true });
  });

  app.post('/__local/reset', (_req, res) => {
    reset();
    res.status(204).end();
  });

  // ---- Cognito Identity Provider JSON API -----------------------------------

  type ActionHandler = (payload: Record<string, unknown>, req: express.Request, res: ExpressResponse) => void;

  const userNotFound = (res: ExpressResponse, message = 'User does not exist.'): void => {
    res.status(400).json({ __type: 'UserNotFoundException', message });
  };

  const passwordPolicyRefusal = (res: ExpressResponse, issue: string): void => {
    res.status(400).json({ __type: 'InvalidPasswordException', message: `Password does not conform to policy: ${issue}` });
  };

  const actions: Record<string, ActionHandler> = {
    InitiateAuth(payload, req, res) {
      const authFlow = String(payload.AuthFlow ?? '').trim();
      const authParams = (payload.AuthParameters ?? {}) as Record<string, unknown>;

      if (String(payload.ClientId ?? '').trim() !== clientId) {
        res.status(400).json({ __type: 'NotAuthorizedException', message: 'Invalid client id.' });
        return;
      }

      if (authFlow === 'USER_PASSWORD_AUTH') {
        const username = String(authParams.USERNAME ?? '').trim();
        const password = String(authParams.PASSWORD ?? '');
        if (!username || !password) {
          res.status(400).json({ __type: 'InvalidParameterException', message: 'USERNAME and PASSWORD are required.' });
          return;
        }

        const user = findByLogin(username);
        if (!user || user.password !== password) {
          res.status(400).json({ __type: 'NotAuthorizedException', message: 'Incorrect username or password.' });
          return;
        }

        const sessionId = randomUUID();
        // USER_PASSWORD_AUTH does not pass through /oauth2/authorize, so no
        // caller states a scope. Real Cognito grants
        // `aws.cognito.signin.user.admin` on this flow.
        const scope = defaultScope;
        const issuer = issuerFor(req);
        const { idToken, accessToken } = issueTokens(user, scope, clientId, sessionId, issuer);
        const refreshToken = createRandomValue(32);
        refreshTokensByValue.set(refreshToken, { userId: user.userId, clientId, scope, sessionId, issuer });

        res.json({
          AuthenticationResult: {
            AccessToken: accessToken,
            IdToken: idToken,
            RefreshToken: refreshToken,
            ExpiresIn: tokenTtlSeconds,
            TokenType: 'Bearer',
          },
          ChallengeParameters: {},
        });
        return;
      }

      if (authFlow === 'REFRESH_TOKEN_AUTH' || authFlow === 'REFRESH_TOKEN') {
        const refreshToken = String(authParams.REFRESH_TOKEN ?? '').trim();
        if (!refreshToken) {
          res.status(400).json({ __type: 'InvalidParameterException', message: 'REFRESH_TOKEN is required.' });
          return;
        }

        const record = refreshTokensByValue.get(refreshToken);
        const user = record ? findById(record.userId) : undefined;
        if (!record || !user) {
          // A deleted user's refresh token is dropped too.
          refreshTokensByValue.delete(refreshToken);
          res.status(400).json({ __type: 'NotAuthorizedException', message: 'Refresh Token has expired' });
          return;
        }

        const { idToken, accessToken } = issueTokens(user, record.scope, record.clientId, record.sessionId, record.issuer);
        // REFRESH_TOKEN_AUTH does not return a new refresh token, as in Cognito.
        res.json({
          AuthenticationResult: {
            AccessToken: accessToken,
            IdToken: idToken,
            ExpiresIn: tokenTtlSeconds,
            TokenType: 'Bearer',
          },
          ChallengeParameters: {},
        });
        return;
      }

      res.status(400).json({
        __type: 'InvalidParameterException',
        message: `Auth flow ${authFlow} is not supported by the local emulator.`,
      });
    },

    ListUsers(payload, _req, res) {
      // Real Cognito only accepts a Filter on a fixed set of standard
      // attributes; a filter on a custom attribute is rejected with
      // InvalidParameterException. An emulator that ignores Filter lets a
      // broken filter pass locally and fail in production.
      const rawFilter = typeof payload.Filter === 'string' ? payload.Filter.trim() : '';
      let filterAttribute: string | undefined;
      let filterValue = '';
      let filterIsPrefix = false;
      if (rawFilter.length > 0) {
        const match = /^([\w:]+)\s*(\^?=)\s*"(.*)"$/.exec(rawFilter);
        filterAttribute = match?.[1];
        filterIsPrefix = match?.[2] === '^=';
        filterValue = match?.[3] ?? '';
        if (!filterAttribute || !COGNITO_FILTERABLE_ATTRIBUTES.has(filterAttribute)) {
          res.status(400).json({ __type: 'InvalidParameterException', message: 'Input fails to satisfy the constraints.' });
          return;
        }
      }

      // ListUsers returns attributes in `Attributes`; AdminGetUser uses
      // `UserAttributes`.
      let listed = users.map((user) => {
        const createdAtEpoch = toEpochSeconds(user.createdAt);
        return {
          Username: user.userId,
          Attributes: toCognitoUserAttributes(user),
          Enabled: true,
          UserStatus: userStatus(user),
          UserCreateDate: createdAtEpoch,
          UserLastModifiedDate: createdAtEpoch,
        };
      });

      // APPLY the filter. Validating it and then returning every user would
      // make a lookup by email match the first user in the pool locally and
      // the right one in production.
      if (filterAttribute) {
        const needle = filterValue.toLowerCase();
        listed = listed.filter((user) => {
          const attributeValue = filterAttribute === 'username'
            ? user.Username
            : filterAttribute === 'cognito:user_status' || filterAttribute === 'status'
              ? user.UserStatus
              : user.Attributes.find((a) => a.Name === filterAttribute)?.Value;
          if (attributeValue === undefined) return false;
          const haystack = attributeValue.toLowerCase();
          return filterIsPrefix ? haystack.startsWith(needle) : haystack === needle;
        });
      }

      const limit = typeof payload.Limit === 'number' ? payload.Limit : undefined;
      res.json({ Users: limit === undefined ? listed : listed.slice(0, limit) });
    },

    AdminGetUser(payload, _req, res) {
      const user = findByLogin(String(payload.Username ?? ''));
      if (!user) {
        userNotFound(res);
        return;
      }
      const createdAtEpoch = toEpochSeconds(user.createdAt);
      res.json({
        Username: user.userId,
        UserAttributes: toCognitoUserAttributes(user),
        UserCreateDate: createdAtEpoch,
        UserLastModifiedDate: createdAtEpoch,
        Enabled: true,
        // An invited account that has never set a password is
        // FORCE_CHANGE_PASSWORD, exactly as Cognito reports it.
        UserStatus: userStatus(user),
      });
    },

    AdminListGroupsForUser(payload, _req, res) {
      const user = findByLogin(String(payload.Username ?? ''));
      if (!user) {
        userNotFound(res);
        return;
      }
      res.json({ Groups: user.groups.map((groupName) => ({ GroupName: groupName })) });
    },

    AdminAddUserToGroup(payload, _req, res) {
      const user = findByLogin(String(payload.Username ?? ''));
      const groupName = String(payload.GroupName ?? '').trim();
      if (!user || !groupName) {
        userNotFound(res, 'User not found.');
        return;
      }
      if (!user.groups.some((g) => g.toLowerCase() === groupName.toLowerCase())) {
        user.groups.push(groupName);
      }
      res.json({});
    },

    AdminRemoveUserFromGroup(payload, _req, res) {
      const user = findByLogin(String(payload.Username ?? ''));
      const groupName = String(payload.GroupName ?? '').trim();
      if (!user || !groupName) {
        userNotFound(res, 'User not found.');
        return;
      }
      user.groups = user.groups.filter((g) => g.toLowerCase() !== groupName.toLowerCase());
      res.json({});
    },

    AdminUserGlobalSignOut(payload, _req, res) {
      // Cognito groups ride in the JWT, so an app that changes a user's groups
      // signs the user out to force a fresh token. Drops the user's refresh
      // tokens; access tokens already issued stay valid until they expire, as
      // in Cognito.
      const user = findByLogin(String(payload.Username ?? ''));
      if (!user) {
        userNotFound(res, 'User not found.');
        return;
      }
      for (const [value, record] of refreshTokensByValue) {
        if (record.userId === user.userId) refreshTokensByValue.delete(value);
      }
      res.json({});
    },

    AdminCreateUser(payload, _req, res) {
      const username = String(payload.Username ?? '').trim();
      const tempPasswordRaw = String(payload.TemporaryPassword ?? '').trim();
      const userAttrs = readAttributes(payload.UserAttributes);
      const email = (userAttrs.find((a) => a.Name === 'email')?.Value ?? username).trim();
      const givenName = userAttrs.find((a) => a.Name === 'given_name')?.Value?.trim() ?? '';
      const familyName = userAttrs.find((a) => a.Name === 'family_name')?.Value?.trim() ?? '';
      // No fallback to the email: real Cognito stores exactly the attributes it
      // was given, so an invited user has NO name until something supplies one.
      const displayName = [givenName, familyName].filter(Boolean).join(' ');

      if (!email || !isValidEmailFormat(email)) {
        res.status(400).json({ __type: 'InvalidParameterException', message: 'Invalid email address format.' });
        return;
      }

      if (tempPasswordRaw) {
        const passwordIssue = validateCognitoDefaultPasswordPolicy(tempPasswordRaw);
        if (passwordIssue) {
          passwordPolicyRefusal(res, passwordIssue);
          return;
        }
      }

      if (users.some((u) => u.email.toLowerCase() === email.toLowerCase())) {
        res.status(400).json({ __type: 'UsernameExistsException', message: 'User already exists.' });
        return;
      }

      // Honour whatever `email_verified` was sent rather than defaulting to
      // verified, so the emulator cannot quietly make a suite greener than
      // production.
      const emailVerifiedAttr = userAttrs.find((a) => a.Name === 'email_verified')?.Value?.trim();
      const newUser: MutableUser = {
        userId: randomUUID(),
        email,
        name: displayName,
        groups: [...(options.newUserGroups ?? [])],
        password: tempPasswordRaw || COGNITO_EMULATOR_DEFAULT_PASSWORD,
        emailVerified: emailVerifiedAttr === undefined ? true : emailVerifiedAttr === 'true',
        forceChangePassword: true,
        customAttributes: customAttributesFrom(userAttrs),
        softwareTokenMfaEnabled: false,
        createdAt: new Date().toISOString(),
      };
      users.push(newUser);

      const createdAtEpoch = toEpochSeconds(newUser.createdAt);
      res.json({
        User: {
          Username: newUser.userId,
          Attributes: toCognitoUserAttributes(newUser),
          Enabled: true,
          UserStatus: userStatus(newUser),
          UserCreateDate: createdAtEpoch,
          UserLastModifiedDate: createdAtEpoch,
        },
      });
    },

    AdminUpdateUserAttributes(payload, _req, res) {
      const user = findByLogin(String(payload.Username ?? ''));
      if (!user) {
        userNotFound(res);
        return;
      }
      const userAttrs = readAttributes(payload.UserAttributes);
      const givenAttr = userAttrs.find((a) => a.Name === 'given_name');
      const familyAttr = userAttrs.find((a) => a.Name === 'family_name');
      if (givenAttr || familyAttr) {
        const [currentGiven = '', ...currentFamily] = user.name.trim().split(/\s+/).filter(Boolean);
        const givenName = givenAttr?.Value?.trim() ?? currentGiven;
        const familyName = familyAttr?.Value?.trim() ?? currentFamily.join(' ');
        user.name = [givenName, familyName].filter(Boolean).join(' ');
      }
      const emailVerifiedAttr = userAttrs.find((a) => a.Name === 'email_verified')?.Value?.trim();
      if (emailVerifiedAttr !== undefined) {
        user.emailVerified = emailVerifiedAttr === 'true';
      }
      Object.assign(user.customAttributes, customAttributesFrom(userAttrs));
      res.json({});
    },

    AdminSetUserPassword(payload, _req, res) {
      const user = findByLogin(String(payload.Username ?? ''));
      const password = String(payload.Password ?? '');
      if (!user) {
        userNotFound(res, 'User not found.');
        return;
      }
      const passwordIssue = validateCognitoDefaultPasswordPolicy(password);
      if (passwordIssue) {
        passwordPolicyRefusal(res, passwordIssue);
        return;
      }
      user.password = password;
      // A permanent password moves the account from FORCE_CHANGE_PASSWORD to
      // CONFIRMED. A temporary one leaves it where it is.
      if (payload.Permanent === true) {
        user.forceChangePassword = false;
      }
      res.json({});
    },

    AdminDeleteUser(payload, _req, res) {
      const user = findByLogin(String(payload.Username ?? ''));
      if (!user) {
        userNotFound(res, 'User not found.');
        return;
      }
      users.splice(users.indexOf(user), 1);
      for (const [value, record] of refreshTokensByValue) {
        if (record.userId === user.userId) refreshTokensByValue.delete(value);
      }
      forgotPasswordCodesByUserId.delete(user.userId);
      res.json({});
    },

    // ---- Forgotten password -------------------------------------------------
    //
    // Modelled with Cognito's OWN refusals, because a client branches on every
    // one of them.

    ForgotPassword(payload, _req, res) {
      // Checked first, exactly as InitiateAuth does. A wrong client id is a
      // misconfigured app, and it must not look like a missing account.
      if (String(payload.ClientId ?? '').trim() !== clientId) {
        res.status(400).json({ __type: 'NotAuthorizedException', message: 'Invalid client id.' });
        return;
      }

      const user = findByLogin(String(payload.Username ?? ''));
      if (!user) {
        userNotFound(res);
        return;
      }

      // Never activated: there is no password to reset, only one to set.
      if (user.forceChangePassword) {
        res.status(400).json({
          __type: 'NotAuthorizedException',
          message: 'User password cannot be reset in the current state.',
        });
        return;
      }

      // With account recovery set to `verified_email`, an unverified address
      // is nowhere to send a code to.
      if (!user.emailVerified) {
        res.status(400).json({
          __type: 'InvalidParameterException',
          message: 'Cannot reset password for the user as there is no registered/verified email or phone_number',
        });
        return;
      }

      const code = String(randomInt(0, 1_000_000)).padStart(6, '0');
      forgotPasswordCodesByUserId.set(user.userId, { code, expiresAtMs: Date.now() + FORGOT_PASSWORD_CODE_TTL_MS });

      res.json({
        CodeDeliveryDetails: {
          DeliveryMedium: 'EMAIL',
          AttributeName: 'email',
          Destination: maskEmailDestination(user.email),
        },
      });
    },

    ConfirmForgotPassword(payload, _req, res) {
      if (String(payload.ClientId ?? '').trim() !== clientId) {
        res.status(400).json({ __type: 'NotAuthorizedException', message: 'Invalid client id.' });
        return;
      }

      const user = findByLogin(String(payload.Username ?? ''));
      const record = user ? forgotPasswordCodesByUserId.get(user.userId) : undefined;
      // An unknown user and a user with no outstanding code answer alike. A
      // separate UserNotFoundException here would allow account enumeration.
      if (!user || !record || record.code !== String(payload.ConfirmationCode ?? '').trim()) {
        res.status(400).json({
          __type: 'CodeMismatchException',
          message: 'Invalid verification code provided, please try again.',
        });
        return;
      }

      if (record.expiresAtMs <= Date.now()) {
        res.status(400).json({
          __type: 'ExpiredCodeException',
          message: 'Invalid code provided, please request a code again.',
        });
        return;
      }

      // Checked AFTER the code, as Cognito does. Checking it first would let a
      // caller with no code learn the policy.
      const password = String(payload.Password ?? '');
      const passwordIssue = validateCognitoDefaultPasswordPolicy(password);
      if (passwordIssue) {
        passwordPolicyRefusal(res, passwordIssue);
        return;
      }

      user.password = password;
      forgotPasswordCodesByUserId.delete(user.userId);
      // Cognito revokes every refresh token on a password reset. Without this
      // a session opened with the OLD password keeps refreshing.
      for (const [value, tokenRecord] of refreshTokensByValue) {
        if (tokenRecord.userId === user.userId) refreshTokensByValue.delete(value);
      }
      res.json({});
    },

    // ---- Self-service and TOTP enrolment ------------------------------------

    GetUser(payload, _req, res) {
      const user = resolveSelfServiceUser(String(payload.AccessToken ?? ''), res);
      if (!user) return;
      res.json({
        Username: user.userId,
        UserAttributes: toCognitoUserAttributes(user),
        UserMFASettingList: user.softwareTokenMfaEnabled ? ['SOFTWARE_TOKEN_MFA'] : [],
        PreferredMfaSetting: user.softwareTokenMfaEnabled ? 'SOFTWARE_TOKEN_MFA' : undefined,
      });
    },

    AssociateSoftwareToken(payload, _req, res) {
      const user = resolveSelfServiceUser(String(payload.AccessToken ?? ''), res);
      if (!user) return;
      // A stable, obviously fake base32 secret. Real Cognito issues a random
      // one; a client does not depend on its value, only that it round-trips.
      user.softwareTokenSecret = `LOCALTOTPSECRET${user.userId.replace(/[^A-Za-z0-9]/g, '').slice(0, 8).toUpperCase()}`;
      res.json({ SecretCode: user.softwareTokenSecret });
    },

    VerifySoftwareToken(payload, _req, res) {
      const user = resolveSelfServiceUser(String(payload.AccessToken ?? ''), res);
      if (!user) return;
      if (!user.softwareTokenSecret) {
        res.status(400).json({
          __type: 'ResourceNotFoundException',
          message: 'No software token has been associated for this user.',
        });
        return;
      }
      // The local stand-in for "the code your authenticator shows": any
      // six-digit code is accepted EXCEPT `000000`, which is the refusal path.
      // A real TOTP check is time-based and cannot be asserted
      // deterministically, so the emulator models the OUTCOMES a client
      // branches on rather than the algorithm.
      const code = String(payload.UserCode ?? '').trim();
      if (!/^\d{6}$/.test(code) || code === '000000') {
        res.status(400).json({
          __type: 'EnableSoftwareTokenMFAException',
          message: 'Code mismatch and fail enable Software Token MFA',
        });
        return;
      }
      res.json({ Status: 'SUCCESS' });
    },

    SetUserMFAPreference(payload, _req, res) {
      const user = resolveSelfServiceUser(String(payload.AccessToken ?? ''), res);
      if (!user) return;
      const pref = (payload.SoftwareTokenMfaSettings ?? {}) as { Enabled?: boolean };
      user.softwareTokenMfaEnabled = pref.Enabled === true;
      if (!user.softwareTokenMfaEnabled) user.softwareTokenSecret = undefined;
      res.json({});
    },
  };

  app.post('/', (req, res, next) => {
    const targetHeader = req.header('x-amz-target')?.trim();
    if (!targetHeader) {
      next();
      return;
    }

    const actionName = targetHeader.split('.').pop() ?? '';
    const handler = Object.prototype.hasOwnProperty.call(actions, actionName) ? actions[actionName] : undefined;
    if (!handler) {
      res.status(400).json({
        __type: 'UnknownOperationException',
        message: `The local emulator does not implement ${actionName}.`,
      });
      return;
    }
    handler(parseAwsJsonBody(req.body), req, res);
  });

  return {
    app,
    clientId,
    listUsers: () => users.map(toRecord),
    getUser: (userIdOrEmail) => {
      const user = findByLogin(userIdOrEmail);
      return user ? toRecord(user) : null;
    },
    reset,
  };
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

export interface StartCognitoEmulatorOptions extends CognitoEmulatorOptions {
  /** Default `COGNITO_EMULATOR_PORT` env var, else 38303. Pass 0 for a free port. */
  readonly port?: number;
  readonly host?: string;
}

export async function startCognitoEmulator(
  options: StartCognitoEmulatorOptions = {},
): Promise<RunningSimulator & { readonly emulator: CognitoEmulator; readonly jwksUrl: string }> {
  const port = options.port ?? Number(process.env.COGNITO_EMULATOR_PORT ?? COGNITO_EMULATOR_DEFAULT_PORT);
  const emulator = createCognitoEmulator(options);
  const running = await listen(emulator.app, port, options.host);

  const issuer = options.issuer ?? running.url;
  console.log(`Cognito emulator: ${issuer}`);
  console.log(`  authorize: ${issuer}/oauth2/authorize`);
  console.log(`  token: ${issuer}/oauth2/token`);
  console.log(`  jwks: ${issuer}/.well-known/jwks.json`);
  return { ...running, emulator, jwksUrl: `${issuer}/.well-known/jwks.json` };
}
