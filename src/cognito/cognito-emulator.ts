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
 *      InitiateAuth (USER_PASSWORD_AUTH, REFRESH_TOKEN_AUTH),
 *      RespondToAuthChallenge (NEW_PASSWORD_REQUIRED), ListUsers,
 *      AdminGetUser, AdminCreateUser, AdminUpdateUserAttributes,
 *      AdminSetUserPassword, AdminDeleteUser, AdminDisableUser,
 *      AdminEnableUser, AdminListGroupsForUser, ListUsersInGroup, AdminAddUserToGroup,
 *      AdminRemoveUserFromGroup, AdminUserGlobalSignOut, ForgotPassword,
 *      ConfirmForgotPassword, GetUser, AssociateSoftwareToken,
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
 *   GET  /__local/invitation?email=…                  – the invitation AdminCreateUser sent, or null
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
  /** Cognito `Enabled`. A disabled user cannot sign in. Default true. */
  readonly enabled?: boolean;
  /**
   * Custom attributes WITHOUT the `custom:` prefix, e.g. `{ tenantId: 'a' }`.
   * They appear as `custom:tenantId` on the ID token, ListUsers and AdminGetUser.
   */
  readonly customAttributes?: Readonly<Record<string, string>>;
}

/**
 * The user pool password policy, as `Policies.PasswordPolicy` on a real pool.
 * Every field is optional; an absent field takes the Cognito default from
 * `COGNITO_DEFAULT_PASSWORD_POLICY`.
 */
export interface CognitoPasswordPolicy {
  /** 6 to 99, as Cognito allows. Default 8. */
  readonly minimumLength?: number;
  readonly requireLowercase?: boolean;
  readonly requireUppercase?: boolean;
  readonly requireNumbers?: boolean;
  readonly requireSymbols?: boolean;
}

/** The policy a new Cognito user pool gets when it names none. */
export const COGNITO_DEFAULT_PASSWORD_POLICY: Required<CognitoPasswordPolicy> = Object.freeze({
  minimumLength: 8,
  requireLowercase: true,
  requireUppercase: true,
  requireNumbers: true,
  requireSymbols: true,
});

/** The invitation AdminCreateUser sent, which real Cognito would email. */
export interface CognitoInvitation {
  readonly userId: string;
  readonly email: string;
  readonly temporaryPassword: string;
  readonly deliveryMediums: readonly string[];
  readonly sentAt: string;
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
  /**
   * The pool's password policy, enforced on every password write
   * (AdminCreateUser TemporaryPassword, AdminSetUserPassword,
   * ConfirmForgotPassword, NEW_PASSWORD_REQUIRED). Default
   * `COGNITO_DEFAULT_PASSWORD_POLICY`.
   */
  readonly passwordPolicy?: CognitoPasswordPolicy;
}

/** A user as the emulator holds it. */
export interface CognitoUserRecord {
  readonly userId: string;
  readonly email: string;
  readonly name: string;
  readonly groups: readonly string[];
  readonly emailVerified: boolean;
  readonly forceChangePassword: boolean;
  readonly enabled: boolean;
  readonly customAttributes: Readonly<Record<string, string>>;
  readonly softwareTokenMfaEnabled: boolean;
  readonly createdAt: string;
  readonly lastModifiedAt: string;
}

export interface CognitoEmulator {
  readonly app: express.Express;
  readonly clientId: string;
  /** The current users, in creation order. */
  listUsers(): readonly CognitoUserRecord[];
  getUser(userIdOrEmail: string): CognitoUserRecord | null;
  /** The last invitation AdminCreateUser sent the user, or null (none, or SUPPRESS). */
  getInvitation(userIdOrEmail: string): CognitoInvitation | null;
  /** Resets to the seed users and drops every code, session, invitation and refresh token. */
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
  enabled: boolean;
  customAttributes: Record<string, string>;
  softwareTokenSecret?: string;
  softwareTokenMfaEnabled: boolean;
  createdAt: string;
  lastModifiedAt: string;
}

/** The access-token claims this emulator reads back from a token it minted. */
interface AccessTokenClaims {
  readonly sub?: string;
  readonly token_use?: string;
  readonly scope?: string;
  readonly origin_jti?: string;
}

/** A NEW_PASSWORD_REQUIRED challenge InitiateAuth issued, keyed by its `Session`. */
interface NewPasswordChallengeRecord {
  readonly userId: string;
  readonly issuer: string;
  readonly expiresAtMs: number;
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
/** Cognito's default `AuthSessionValidity`: a challenge must be answered within 3 minutes. */
const CHALLENGE_SESSION_TTL_MS = 3 * 60 * 1000;
/** ListUsers `Limit` range is 0..60, and 60 is also the page size when no Limit is sent. */
const LIST_USERS_MAX_LIMIT = 60;
const DELIVERY_MEDIUMS = new Set(['EMAIL', 'SMS']);

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

/** The characters Cognito counts as symbols in a password policy. */
const COGNITO_PASSWORD_SYMBOL = /[\^$*.[\]{}()?\-"!@#%&/\\,><':;|_~`+=]/;

/**
 * The first rule of `policy` that `password` breaks, as the text Cognito puts
 * after "Password does not conform to policy: ", or null. Fields `policy`
 * leaves out take their `COGNITO_DEFAULT_PASSWORD_POLICY` value.
 */
export function validateCognitoPasswordPolicy(password: string, policy: CognitoPasswordPolicy = {}): string | null {
  const effective = { ...COGNITO_DEFAULT_PASSWORD_POLICY, ...policy };
  if (password.length < effective.minimumLength) return 'Password not long enough';
  if (password.length > 256) return 'Password must have length less than or equal to 256';
  if (effective.requireUppercase && !/[A-Z]/.test(password)) return 'Password must have uppercase characters';
  if (effective.requireLowercase && !/[a-z]/.test(password)) return 'Password must have lowercase characters';
  if (effective.requireNumbers && !/[0-9]/.test(password)) return 'Password must have numeric characters';
  if (effective.requireSymbols && !COGNITO_PASSWORD_SYMBOL.test(password)) return 'Password must have symbol characters';
  return null;
}

/** The first rule of Cognito's default password policy that `password` breaks, or null. */
export function validateCognitoDefaultPasswordPolicy(password: string): string | null {
  return validateCognitoPasswordPolicy(password, COGNITO_DEFAULT_PASSWORD_POLICY);
}

/** A policy Cognito would accept on CreateUserPool, with its defaults filled in; throws otherwise. */
function resolvePasswordPolicy(policy: CognitoPasswordPolicy | undefined): Required<CognitoPasswordPolicy> {
  const effective = { ...COGNITO_DEFAULT_PASSWORD_POLICY, ...(policy ?? {}) };
  const { minimumLength } = effective;
  if (!Number.isInteger(minimumLength) || minimumLength < 6 || minimumLength > 99) {
    throw new Error(`passwordPolicy.minimumLength must be an integer from 6 to 99, as Cognito allows; got ${minimumLength}.`);
  }
  return effective;
}

/**
 * A temporary password that meets `policy`, as Cognito generates when
 * AdminCreateUser is sent no TemporaryPassword. Always holds one character of
 * every class, so it passes whichever rules are on.
 */
function generateTemporaryPassword(policy: Required<CognitoPasswordPolicy>): string {
  const filler = randomBytes(96).toString('base64').replace(/[^A-Za-z0-9]/g, '');
  const body = `Tq7!${filler}`;
  return body.slice(0, Math.max(policy.minimumLength, 12));
}

function isValidEmailFormat(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function toEpochSeconds(isoTimestamp: string): number {
  const epochMs = Date.parse(isoTimestamp);
  return Number.isFinite(epochMs) ? Math.floor(epochMs / 1000) : 0;
}

interface ListUsersToken {
  readonly offset: number;
  readonly filter: string;
}

/** An opaque ListUsers PaginationToken: where the next page starts, and the Filter it continues. */
function encodeListUsersToken(token: ListUsersToken): string {
  return toBase64Url(JSON.stringify(token));
}

function decodeListUsersToken(value: string): ListUsersToken | undefined {
  try {
    const parsed = JSON.parse(Buffer.from(value, 'base64url').toString('utf8')) as Partial<ListUsersToken>;
    if (typeof parsed.offset !== 'number' || !Number.isInteger(parsed.offset) || parsed.offset < 0) return undefined;
    if (typeof parsed.filter !== 'string') return undefined;
    return { offset: parsed.offset, filter: parsed.filter };
  } catch {
    return undefined;
  }
}

interface ListUsersInGroupToken {
  readonly offset: number;
  readonly group: string;
}

/** An opaque ListUsersInGroup NextToken: where the next page starts, and the group it continues. */
function encodeListUsersInGroupToken(token: ListUsersInGroupToken): string {
  return toBase64Url(JSON.stringify(token));
}

function decodeListUsersInGroupToken(value: string): ListUsersInGroupToken | undefined {
  try {
    const parsed = JSON.parse(Buffer.from(value, 'base64url').toString('utf8')) as Partial<ListUsersInGroupToken>;
    if (typeof parsed.offset !== 'number' || !Number.isInteger(parsed.offset) || parsed.offset < 0) return undefined;
    if (typeof parsed.group !== 'string') return undefined;
    return { offset: parsed.offset, group: parsed.group };
  } catch {
    return undefined;
  }
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
    enabled: user.enabled,
    customAttributes: { ...user.customAttributes },
    softwareTokenMfaEnabled: user.softwareTokenMfaEnabled,
    createdAt: user.createdAt,
    lastModifiedAt: user.lastModifiedAt,
  };
}

/**
 * The Cognito `UserType` ListUsers and AdminCreateUser return. AdminGetUser
 * returns the same fields with the attributes under `UserAttributes`.
 */
function toUserType(user: MutableUser) {
  return {
    Username: user.userId,
    Attributes: toCognitoUserAttributes(user),
    Enabled: user.enabled,
    UserStatus: userStatus(user),
    UserCreateDate: toEpochSeconds(user.createdAt),
    UserLastModifiedDate: toEpochSeconds(user.lastModifiedAt),
  };
}

function fromSeed(seed: CognitoSeedUser): MutableUser {
  const seededAt = new Date(0).toISOString();
  return {
    userId: seed.userId,
    email: seed.email,
    name: seed.name,
    groups: [...seed.groups],
    password: seed.password ?? COGNITO_EMULATOR_DEFAULT_PASSWORD,
    emailVerified: seed.emailVerified ?? true,
    forceChangePassword: seed.forceChangePassword ?? false,
    enabled: seed.enabled ?? true,
    customAttributes: { ...(seed.customAttributes ?? {}) },
    softwareTokenMfaEnabled: false,
    createdAt: seededAt,
    lastModifiedAt: seededAt,
  };
}

/** Records a change to the user, so UserLastModifiedDate moves as it does in Cognito. */
function touch(user: MutableUser): void {
  user.lastModifiedAt = new Date().toISOString();
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
            <span class="btn-meta">${escapeHtml(user.email)} &middot; ${escapeHtml(user.groups.join(', '))}${user.enabled ? '' : ' &middot; disabled'}</span>
          </button>`;
    })
    .join('\n          ');

  return renderHostedUiPage(`
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
      </form>`);
}

/** The hosted-UI page chrome every sign-in page shares. */
function renderHostedUiPage(content: string): string {
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
      .error { margin-top: 1rem; padding: 0.75rem; background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; color: #991b1b; }
      input[type=password] { padding: 0.6rem; border: 1px solid #cbd5e1; border-radius: 8px; font-size: 0.95rem; }
      button { appearance: none; border: 1px solid #cbd5e1; border-radius: 8px; padding: 0.75rem 1rem; background: #fff; color: #0f172a; font-size: 0.95rem; cursor: pointer; text-align: left; display: flex; flex-direction: column; gap: 0.2rem; }
      button:hover { background: #f1f5f9; border-color: #2563eb; }
      .btn-name { font-weight: 600; }
      .btn-meta { font-size: 0.82rem; color: #64748b; }
    </style>
  </head>
  <body>
    <main class="container">
      <h1>Local OAuth Simulator</h1>${content}
    </main>
  </body>
</html>`;
}

function renderSignInError(message: string): string {
  return `
      <div class="error" data-testid="local-auth-error">${escapeHtml(message)}</div>`;
}

/**
 * The page the hosted UI shows a FORCE_CHANGE_PASSWORD user after sign-in:
 * choose a new password before any code is issued. It posts back to
 * /oauth2/authorize with every authorize parameter plus `new_password`.
 */
function renderNewPasswordPage(params: Record<string, string>, user: MutableUser, error?: string): string {
  const hidden = Object.entries({ ...params, selected_user: user.userId, continue: '1' })
    .map(([name, value]) => `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}" />`)
    .join('\n        ');
  return renderHostedUiPage(`
      <p>Change Password</p>
      <p>Please enter a new password for ${escapeHtml(user.email)}.</p>${error ? renderSignInError(error) : ''}
      <form method="post" action="/oauth2/authorize">
        ${hidden}
        <div class="actions">
          <input type="password" name="new_password" autocomplete="new-password" data-testid="local-auth-new-password" />
          <button type="submit" data-testid="local-auth-new-password-submit"><span class="btn-name">Send</span></button>
        </div>
      </form>`);
}

// ---------------------------------------------------------------------------
// Emulator factory
// ---------------------------------------------------------------------------

export function createCognitoEmulator(options: CognitoEmulatorOptions = {}): CognitoEmulator {
  const clientId = options.clientId ?? COGNITO_EMULATOR_DEFAULT_CLIENT_ID;
  const tokenTtlSeconds = options.tokenTtlSeconds ?? 3600;
  const defaultScope = options.defaultScope ?? COGNITO_EMULATOR_DEFAULT_SCOPE;
  const seedUsers = options.users ?? [];
  // Checked at start-up: a policy real Cognito would refuse fails here, not
  // on the first password write.
  const passwordPolicy = resolvePasswordPolicy(options.passwordPolicy);

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
  /** Outstanding NEW_PASSWORD_REQUIRED challenges, keyed by `Session`. Single use. */
  const newPasswordChallenges = new Map<string, NewPasswordChallengeRecord>();
  /** The last invitation AdminCreateUser sent each user, keyed by user id. */
  const invitationsByUserId = new Map<string, CognitoInvitation>();
  /**
   * Sign-in sessions (`origin_jti`) whose access tokens Cognito no longer
   * accepts, after AdminDisableUser or AdminUserGlobalSignOut.
   */
  const revokedSessionIds = new Set<string>();

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

    if (claims.origin_jti && revokedSessionIds.has(claims.origin_jti)) {
      res.status(400).json({ __type: 'NotAuthorizedException', message: 'Access Token has been revoked' });
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
    newPasswordChallenges.clear();
    invitationsByUserId.clear();
    revokedSessionIds.clear();
    users.length = 0;
    users.push(...seedUsers.map(fromSeed));
  }

  /**
   * Revokes every sign-in session the user holds: the refresh tokens stop
   * refreshing and the access tokens stop authorising Cognito API calls, as
   * AdminDisableUser and AdminUserGlobalSignOut do in Cognito. A JWT verifier
   * in the app still accepts an access token until it expires, as with real
   * Cognito.
   */
  function revokeSessions(user: MutableUser): void {
    for (const [value, record] of refreshTokensByValue) {
      if (record.userId !== user.userId) continue;
      revokedSessionIds.add(record.sessionId);
      refreshTokensByValue.delete(value);
    }
  }

  function passwordIssue(password: string): string | null {
    return validateCognitoPasswordPolicy(password, passwordPolicy);
  }

  /**
   * Issues tokens plus a refresh token for a sign-in that did not pass through
   * /oauth2/authorize, so no caller states a scope. Real Cognito grants
   * `aws.cognito.signin.user.admin` on these flows.
   */
  function issueSignInResult(user: MutableUser, issuer: string) {
    const sessionId = randomUUID();
    const scope = defaultScope;
    const { idToken, accessToken } = issueTokens(user, scope, clientId, sessionId, issuer);
    const refreshToken = createRandomValue(32);
    refreshTokensByValue.set(refreshToken, { userId: user.userId, clientId, scope, sessionId, issuer });
    return {
      AuthenticationResult: {
        AccessToken: accessToken,
        IdToken: idToken,
        RefreshToken: refreshToken,
        ExpiresIn: tokenTtlSeconds,
        TokenType: 'Bearer',
      },
      ChallengeParameters: {},
    };
  }

  /** Stores the name parts, `email_verified` and custom attributes in `attrs`. */
  function applyAttributes(user: MutableUser, attrs: Array<{ Name?: string; Value?: string }>): void {
    const givenAttr = attrs.find((a) => a.Name === 'given_name');
    const familyAttr = attrs.find((a) => a.Name === 'family_name');
    if (givenAttr || familyAttr) {
      const [currentGiven = '', ...currentFamily] = user.name.trim().split(/\s+/).filter(Boolean);
      const givenName = givenAttr?.Value?.trim() ?? currentGiven;
      const familyName = familyAttr?.Value?.trim() ?? currentFamily.join(' ');
      user.name = [givenName, familyName].filter(Boolean).join(' ');
    }
    const emailVerifiedAttr = attrs.find((a) => a.Name === 'email_verified')?.Value?.trim();
    if (emailVerifiedAttr !== undefined) {
      user.emailVerified = emailVerifiedAttr === 'true';
    }
    Object.assign(user.customAttributes, customAttributesFrom(attrs));
  }

  /** Sets a password the user chose, which ends FORCE_CHANGE_PASSWORD. */
  function setPermanentPassword(user: MutableUser, password: string): void {
    user.password = password;
    user.forceChangePassword = false;
    touch(user);
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

  /**
   * The hosted-UI sign-in. GET shows the user picker and takes the pick; POST
   * carries the new password a FORCE_CHANGE_PASSWORD user chooses. Both read
   * the same parameters, from the query string or the form body.
   */
  function handleAuthorize(input: Record<string, unknown>, req: express.Request, res: ExpressResponse): void {
    const responseType = String(input.response_type ?? '').trim();
    const requestClientId = String(input.client_id ?? '').trim();
    const redirectUri = String(input.redirect_uri ?? '').trim() || (options.defaultRedirectUri ?? '');
    const state = String(input.state ?? '').trim();
    const scope = String(input.scope ?? defaultScope).trim();
    const codeChallenge = String(input.code_challenge ?? '').trim();
    const codeChallengeMethod = String(input.code_challenge_method ?? '').trim();

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

    const pageParams = {
      response_type: responseType,
      client_id: requestClientId,
      redirect_uri: redirectUri,
      state,
      scope,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod,
    };

    if (String(input.continue ?? '').trim() !== '1') {
      res.status(200).type('html').send(renderAuthorizePage(pageParams, users));
      return;
    }

    const selectedUser = resolveUserSelection(String(input.selected_user ?? ''));
    if (!selectedUser) {
      res.status(400).json({ error: 'invalid_request', error_description: 'The emulator has no users to sign in as.' });
      return;
    }

    // Cognito's hosted UI refuses a disabled user on its sign-in page with the
    // same words InitiateAuth uses. No code is issued.
    if (!selectedUser.enabled) {
      res.status(400).type('html').send(renderHostedUiPage(renderSignInError('User is disabled.')));
      return;
    }

    // An invited user, or one given a temporary password, must choose a new
    // password before Cognito issues a code. The picker stands in for the
    // temporary-password step; the new password is checked against the policy.
    if (selectedUser.forceChangePassword) {
      if (req.method !== 'POST') {
        res.status(200).type('html').send(renderNewPasswordPage(pageParams, selectedUser));
        return;
      }
      const newPassword = String(input.new_password ?? '');
      const issue = passwordIssue(newPassword);
      if (issue) {
        res.status(400).type('html').send(renderNewPasswordPage(pageParams, selectedUser, `Password does not conform to policy: ${issue}`));
        return;
      }
      setPermanentPassword(selectedUser, newPassword);
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
  }

  app.get('/oauth2/authorize', (req, res) => handleAuthorize(req.query as Record<string, unknown>, req, res));
  app.post('/oauth2/authorize', (req, res) => handleAuthorize((req.body ?? {}) as Record<string, unknown>, req, res));

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
    if (!user.enabled) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'User is disabled.' });
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
   * The invitation AdminCreateUser sent, or null. Real Cognito emails the
   * temporary password; a test reads the one the product caused to be sent,
   * so the first sign-in runs with the real value.
   */
  app.get('/__local/invitation', (req, res) => {
    const user = findByEmailQuery(req);
    res.json({ invitation: (user && invitationsByUserId.get(user.userId)) ?? null });
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

        // Judged after the password, so a wrong password for a disabled
        // account reads as a wrong password and says nothing about the state.
        if (!user.enabled) {
          res.status(400).json({ __type: 'NotAuthorizedException', message: 'User is disabled.' });
          return;
        }

        // A temporary password signs in only far enough to choose a new one:
        // Cognito answers with the challenge and issues no tokens.
        if (user.forceChangePassword) {
          const session = createRandomValue(48);
          newPasswordChallenges.set(session, {
            userId: user.userId,
            issuer: issuerFor(req),
            expiresAtMs: Date.now() + CHALLENGE_SESSION_TTL_MS,
          });
          const userAttributes = Object.fromEntries(
            toCognitoUserAttributes(user).filter((a) => a.Name !== 'sub').map((a) => [a.Name, a.Value]),
          );
          res.json({
            ChallengeName: 'NEW_PASSWORD_REQUIRED',
            Session: session,
            ChallengeParameters: {
              USER_ID_FOR_SRP: user.userId,
              requiredAttributes: '[]',
              userAttributes: JSON.stringify(userAttributes),
            },
          });
          return;
        }

        res.json(issueSignInResult(user, issuerFor(req)));
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
        if (!user.enabled) {
          res.status(400).json({ __type: 'NotAuthorizedException', message: 'User is disabled.' });
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

    RespondToAuthChallenge(payload, _req, res) {
      if (String(payload.ClientId ?? '').trim() !== clientId) {
        res.status(400).json({ __type: 'NotAuthorizedException', message: 'Invalid client id.' });
        return;
      }

      const challengeName = String(payload.ChallengeName ?? '').trim();
      if (challengeName !== 'NEW_PASSWORD_REQUIRED') {
        res.status(400).json({
          __type: 'InvalidParameterException',
          message: `Challenge ${challengeName} is not supported by the local emulator.`,
        });
        return;
      }

      const session = String(payload.Session ?? '');
      const record = newPasswordChallenges.get(session);
      const user = record ? findById(record.userId) : undefined;
      if (!record || !user) {
        res.status(400).json({ __type: 'NotAuthorizedException', message: 'Invalid session for the user.' });
        return;
      }
      if (record.expiresAtMs <= Date.now()) {
        newPasswordChallenges.delete(session);
        res.status(400).json({ __type: 'NotAuthorizedException', message: 'Invalid session for the user, session is expired.' });
        return;
      }

      const responses = (payload.ChallengeResponses ?? {}) as Record<string, unknown>;
      const username = String(responses.USERNAME ?? '').trim();
      const newPassword = String(responses.NEW_PASSWORD ?? '');
      if (!username || !newPassword) {
        res.status(400).json({
          __type: 'InvalidParameterException',
          message: `Missing required parameter ${username ? 'NEW_PASSWORD' : 'USERNAME'}`,
        });
        return;
      }
      if (findByLogin(username) !== user) {
        res.status(400).json({ __type: 'NotAuthorizedException', message: 'Invalid session for the user.' });
        return;
      }

      // `userAttributes.<name>` sets an attribute alongside the new password.
      // The emulator stores names and custom attributes only; anything else is
      // refused by name rather than dropped.
      const attributes: Array<{ Name: string; Value: string }> = [];
      for (const [key, value] of Object.entries(responses)) {
        if (key === 'USERNAME' || key === 'NEW_PASSWORD') continue;
        const attributeName = key.startsWith('userAttributes.') ? key.slice('userAttributes.'.length) : undefined;
        if (!attributeName || !(attributeName === 'given_name' || attributeName === 'family_name' || attributeName.startsWith('custom:'))) {
          res.status(400).json({
            __type: 'InvalidParameterException',
            message: `The local emulator does not support the challenge response ${attributeName ?? key}.`,
          });
          return;
        }
        attributes.push({ Name: attributeName, Value: String(value) });
      }

      const issue = passwordIssue(newPassword);
      if (issue) {
        passwordPolicyRefusal(res, issue);
        return;
      }

      if (!user.enabled) {
        res.status(400).json({ __type: 'NotAuthorizedException', message: 'User is disabled.' });
        return;
      }

      newPasswordChallenges.delete(session);
      applyAttributes(user, attributes);
      setPermanentPassword(user, newPassword);
      res.json(issueSignInResult(user, record.issuer));
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

      // Limit is 0..60, and an absent Limit means a page of 60.
      const limit = payload.Limit ?? LIST_USERS_MAX_LIMIT;
      if (typeof limit !== 'number' || !Number.isInteger(limit) || limit < 0 || limit > LIST_USERS_MAX_LIMIT) {
        res.status(400).json({
          __type: 'InvalidParameterException',
          message: `1 validation error detected: Value '${String(limit)}' at 'limit' failed to satisfy constraint: Member must have value less than or equal to ${LIST_USERS_MAX_LIMIT}`,
        });
        return;
      }
      const pageSize = limit === 0 ? LIST_USERS_MAX_LIMIT : limit;

      const attributesToGet = payload.AttributesToGet;
      if (attributesToGet !== undefined && (!Array.isArray(attributesToGet) || attributesToGet.some((a) => typeof a !== 'string'))) {
        res.status(400).json({ __type: 'InvalidParameterException', message: 'AttributesToGet must be a list of attribute names.' });
        return;
      }

      // The token names where the next page starts and the Filter it belongs
      // to: a token presented with a different Filter is refused rather than
      // continuing someone else's query.
      let offset = 0;
      if (payload.PaginationToken !== undefined) {
        const token = decodeListUsersToken(String(payload.PaginationToken));
        if (!token || token.filter !== rawFilter) {
          res.status(400).json({ __type: 'InvalidParameterException', message: 'Invalid pagination token.' });
          return;
        }
        offset = token.offset;
      }

      // APPLY the filter. Validating it and then returning every user would
      // make a lookup by email match the first user in the pool locally and
      // the right one in production.
      let matched = users;
      if (filterAttribute) {
        matched = users.filter((user) => {
          // `username` and `status` compare case-sensitively in Cognito; the
          // other attributes do not.
          if (filterAttribute === 'username' || filterAttribute === 'status') {
            const exact = filterAttribute === 'username' ? user.userId : user.enabled ? 'Enabled' : 'Disabled';
            return filterIsPrefix ? exact.startsWith(filterValue) : exact === filterValue;
          }
          const attributeValue = filterAttribute === 'cognito:user_status'
            ? userStatus(user)
            : toCognitoUserAttributes(user).find((a) => a.Name === filterAttribute)?.Value;
          if (attributeValue === undefined) return false;
          const haystack = attributeValue.toLowerCase();
          const needle = filterValue.toLowerCase();
          return filterIsPrefix ? haystack.startsWith(needle) : haystack === needle;
        });
      }

      const page = matched.slice(offset, offset + pageSize).map((user) => {
        const listed = toUserType(user);
        return attributesToGet === undefined
          ? listed
          : { ...listed, Attributes: listed.Attributes.filter((a) => (attributesToGet as string[]).includes(a.Name)) };
      });
      const nextOffset = offset + pageSize;
      res.json({
        Users: page,
        ...(nextOffset < matched.length ? { PaginationToken: encodeListUsersToken({ offset: nextOffset, filter: rawFilter }) } : {}),
      });
    },

    AdminGetUser(payload, _req, res) {
      const user = findByLogin(String(payload.Username ?? ''));
      if (!user) {
        userNotFound(res);
        return;
      }
      // AdminGetUser names the attribute list `UserAttributes`; ListUsers and
      // AdminCreateUser name it `Attributes`.
      const { Attributes, ...rest } = toUserType(user);
      res.json({ ...rest, UserAttributes: Attributes });
    },

    /**
     * The members of one group, a page at a time (Limit 0..60, 60 when absent
     * or 0), as `UserType` objects. The emulator keeps no group objects, so a
     * group nobody is in answers an empty list where Cognito answers
     * ResourceNotFoundException for a group that does not exist. Group names
     * compare without case, as AdminAddUserToGroup does here.
     */
    ListUsersInGroup(payload, _req, res) {
      const groupName = String(payload.GroupName ?? '').trim();
      if (!groupName) {
        res.status(400).json({ __type: 'InvalidParameterException', message: 'GroupName is required.' });
        return;
      }
      const limit = payload.Limit ?? LIST_USERS_MAX_LIMIT;
      if (typeof limit !== 'number' || !Number.isInteger(limit) || limit < 0 || limit > LIST_USERS_MAX_LIMIT) {
        res.status(400).json({
          __type: 'InvalidParameterException',
          message: `1 validation error detected: Value '${String(limit)}' at 'limit' failed to satisfy constraint: Member must have value less than or equal to ${LIST_USERS_MAX_LIMIT}`,
        });
        return;
      }
      const pageSize = limit === 0 ? LIST_USERS_MAX_LIMIT : limit;
      let offset = 0;
      if (payload.NextToken !== undefined) {
        const token = decodeListUsersInGroupToken(String(payload.NextToken));
        if (!token || token.group !== groupName.toLowerCase()) {
          res.status(400).json({ __type: 'InvalidParameterException', message: 'Invalid pagination token.' });
          return;
        }
        offset = token.offset;
      }
      const members = users.filter((user) => user.groups.some((g) => g.toLowerCase() === groupName.toLowerCase()));
      const nextOffset = offset + pageSize;
      res.json({
        Users: members.slice(offset, nextOffset).map(toUserType),
        ...(nextOffset < members.length
          ? { NextToken: encodeListUsersInGroupToken({ offset: nextOffset, group: groupName.toLowerCase() }) }
          : {}),
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
      // signs the user out to force a fresh token. Revokes the user's refresh
      // tokens, and their access tokens for Cognito API calls such as GetUser.
      // An app's own JWT verifier still accepts an access token until it
      // expires, as with Cognito.
      const user = findByLogin(String(payload.Username ?? ''));
      if (!user) {
        userNotFound(res, 'User not found.');
        return;
      }
      revokeSessions(user);
      res.json({});
    },

    AdminDisableUser(payload, _req, res) {
      const user = findByLogin(String(payload.Username ?? ''));
      if (!user) {
        userNotFound(res);
        return;
      }
      // Cognito "deactivates a user profile and revokes all access tokens for
      // the user". Re-enabling does not bring the revoked sessions back.
      user.enabled = false;
      revokeSessions(user);
      touch(user);
      res.json({});
    },

    AdminEnableUser(payload, _req, res) {
      const user = findByLogin(String(payload.Username ?? ''));
      if (!user) {
        userNotFound(res);
        return;
      }
      user.enabled = true;
      touch(user);
      res.json({});
    },

    AdminCreateUser(payload, _req, res) {
      const username = String(payload.Username ?? '').trim();
      const tempPasswordRaw = String(payload.TemporaryPassword ?? '').trim();
      const userAttrs = readAttributes(payload.UserAttributes);

      const messageAction = payload.MessageAction === undefined ? undefined : String(payload.MessageAction);
      if (messageAction !== undefined && messageAction !== 'RESEND' && messageAction !== 'SUPPRESS') {
        res.status(400).json({
          __type: 'InvalidParameterException',
          message: `1 validation error detected: Value '${messageAction}' at 'messageAction' failed to satisfy constraint: Member must satisfy enum value set: [RESEND, SUPPRESS]`,
        });
        return;
      }

      // Cognito's default is SMS.
      const rawMediums: unknown = payload.DesiredDeliveryMediums ?? ['SMS'];
      if (!Array.isArray(rawMediums) || rawMediums.some((m) => !DELIVERY_MEDIUMS.has(String(m)))) {
        res.status(400).json({
          __type: 'InvalidParameterException',
          message: `1 validation error detected: Value '${JSON.stringify(rawMediums)}' at 'desiredDeliveryMediums' failed to satisfy constraint: Member must satisfy enum value set: [SMS, EMAIL]`,
        });
        return;
      }
      const deliveryMediums = rawMediums.map(String);

      if (tempPasswordRaw) {
        const issue = passwordIssue(tempPasswordRaw);
        if (issue) {
          passwordPolicyRefusal(res, issue);
          return;
        }
      }

      /**
       * The emulator stores no phone number, so it cannot say what Cognito
       * does with an SMS invitation. It refuses rather than guess.
       */
      const refuseSmsInvitation = (): boolean => {
        if (messageAction === 'SUPPRESS' || !deliveryMediums.includes('SMS')) return false;
        res.status(400).json({
          __type: 'InvalidParameterException',
          message: 'The local emulator cannot deliver an invitation by SMS (DesiredDeliveryMediums defaults to SMS). '
            + 'Send DesiredDeliveryMediums: ["EMAIL"], or MessageAction: "SUPPRESS".',
        });
        return true;
      };

      const sendInvitation = (user: MutableUser): void => {
        if (messageAction === 'SUPPRESS') return;
        invitationsByUserId.set(user.userId, {
          userId: user.userId,
          email: user.email,
          temporaryPassword: user.password,
          deliveryMediums,
          sentAt: new Date().toISOString(),
        });
      };

      // RESEND: a new temporary password for a user who has not yet set one.
      if (messageAction === 'RESEND') {
        const existing = findByLogin(username);
        if (!existing) {
          userNotFound(res);
          return;
        }
        if (!existing.forceChangePassword) {
          res.status(400).json({
            __type: 'UnsupportedUserStateException',
            message: `Resend not possible. ${username} status is not FORCE_CHANGE_PASSWORD.`,
          });
          return;
        }
        if (refuseSmsInvitation()) return;
        existing.password = tempPasswordRaw || generateTemporaryPassword(passwordPolicy);
        touch(existing);
        sendInvitation(existing);
        res.json({ User: toUserType(existing) });
        return;
      }

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

      if (users.some((u) => u.email.toLowerCase() === email.toLowerCase())) {
        res.status(400).json({ __type: 'UsernameExistsException', message: 'User already exists.' });
        return;
      }

      if (refuseSmsInvitation()) return;

      // Honour whatever `email_verified` was sent rather than defaulting to
      // verified, so the emulator cannot quietly make a suite greener than
      // production.
      const emailVerifiedAttr = userAttrs.find((a) => a.Name === 'email_verified')?.Value?.trim();
      const createdAt = new Date().toISOString();
      const newUser: MutableUser = {
        userId: randomUUID(),
        email,
        name: displayName,
        groups: [...(options.newUserGroups ?? [])],
        // With no TemporaryPassword, Cognito generates one and sends it in the
        // invitation. With SUPPRESS as well, nobody learns it: the account
        // signs in only after AdminSetUserPassword.
        password: tempPasswordRaw || generateTemporaryPassword(passwordPolicy),
        emailVerified: emailVerifiedAttr === undefined ? true : emailVerifiedAttr === 'true',
        forceChangePassword: true,
        enabled: true,
        customAttributes: customAttributesFrom(userAttrs),
        softwareTokenMfaEnabled: false,
        createdAt,
        lastModifiedAt: createdAt,
      };
      users.push(newUser);
      sendInvitation(newUser);

      res.json({ User: toUserType(newUser) });
    },

    AdminUpdateUserAttributes(payload, _req, res) {
      const user = findByLogin(String(payload.Username ?? ''));
      if (!user) {
        userNotFound(res);
        return;
      }
      applyAttributes(user, readAttributes(payload.UserAttributes));
      touch(user);
      res.json({});
    },

    AdminSetUserPassword(payload, _req, res) {
      const user = findByLogin(String(payload.Username ?? ''));
      const password = String(payload.Password ?? '');
      if (!user) {
        userNotFound(res, 'User not found.');
        return;
      }
      const issue = passwordIssue(password);
      if (issue) {
        passwordPolicyRefusal(res, issue);
        return;
      }
      // A permanent password moves the account to CONFIRMED. A temporary one
      // (Permanent false or absent) moves it to FORCE_CHANGE_PASSWORD, even
      // from CONFIRMED, so the next sign-in meets NEW_PASSWORD_REQUIRED.
      if (payload.Permanent === true) {
        setPermanentPassword(user, password);
      } else {
        user.password = password;
        user.forceChangePassword = true;
        touch(user);
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
      invitationsByUserId.delete(user.userId);
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
      const issue = passwordIssue(password);
      if (issue) {
        passwordPolicyRefusal(res, issue);
        return;
      }

      user.password = password;
      touch(user);
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
    getInvitation: (userIdOrEmail) => {
      const user = findByLogin(userIdOrEmail);
      return (user && invitationsByUserId.get(user.userId)) ?? null;
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
