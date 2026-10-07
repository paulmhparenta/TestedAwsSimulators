import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createHash, createPublicKey, verify as verifySignature, type JsonWebKey } from 'node:crypto';
import {
  AdminAddUserToGroupCommand,
  AdminCreateUserCommand,
  AdminDisableUserCommand,
  AdminEnableUserCommand,
  AdminGetUserCommand,
  AdminListGroupsForUserCommand,
  ListUsersInGroupCommand,
  AdminSetUserPasswordCommand,
  AdminUpdateUserAttributesCommand,
  CognitoIdentityProviderClient,
  GetUserCommand,
  InitiateAuthCommand,
  InvalidParameterException,
  InvalidPasswordException,
  ListUsersCommand,
  NotAuthorizedException,
  RespondToAuthChallengeCommand,
  UnsupportedUserStateException,
  UserNotFoundException,
} from '@aws-sdk/client-cognito-identity-provider';

import {
  COGNITO_DEFAULT_PASSWORD_POLICY,
  createCognitoEmulator,
  startCognitoEmulator,
  maskEmailDestination,
  validateCognitoDefaultPasswordPolicy,
  validateCognitoPasswordPolicy,
  type CognitoEmulator,
  type CognitoSeedUser,
} from './cognito-emulator';
import type { RunningSimulator } from '../shared/server';

const CLIENT_ID = 'test-client';
const PASSWORD = 'Password1!';

/**
 * Each seed user exists so a case has a target no other case changes. The
 * module-level `beforeEach` resets the pool to them, so no case depends on order.
 */
const SEED_USERS: CognitoSeedUser[] = [
  { userId: 'admin-001', email: 'admin@example.com', name: 'Ada Admin', groups: ['Admin', 'Users'], customAttributes: { tenantId: 'tenant-a' } },
  { userId: 'user-001', email: 'user@example.com', name: 'Uma User', groups: ['Users'], customAttributes: { tenantId: 'tenant-a' } },
  { userId: 'mfa-001', email: 'mfa@example.com', name: 'Mia Mfa', groups: ['Users'] },
  { userId: 'nomfa-001', email: 'nomfa@example.com', name: 'Nia Nomfa', groups: ['Users'] },
  { userId: 'badcode-001', email: 'badcode@example.com', name: 'Bea Badcode', groups: ['Users'] },
  { userId: 'unverified-001', email: 'pending@example.com', name: 'Pat Pending', groups: ['Users'], emailVerified: false },
];

let running: RunningSimulator & { emulator: CognitoEmulator; jwksUrl: string };
let baseUrl = '';
let sdk: CognitoIdentityProviderClient;

beforeAll(async () => {
  running = await startCognitoEmulator({ port: 0, host: '127.0.0.1', clientId: CLIENT_ID, users: SEED_USERS });
  baseUrl = `http://127.0.0.1:${running.port}`;
  sdk = new CognitoIdentityProviderClient({
    endpoint: baseUrl,
    region: 'us-east-1',
    credentials: { accessKeyId: 'test', secretAccessKey: 'test' },
  });
});

afterAll(async () => {
  sdk.destroy();
  await running.close();
});

beforeEach(() => {
  running.emulator.reset();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function callCognito(action: string, body: Record<string, unknown>): Promise<{ status: number; json: Record<string, unknown> }> {
  const res = await fetch(`${baseUrl}/`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-amz-json-1.1',
      'X-Amz-Target': `AWSCognitoIdentityProviderService.${action}`,
    },
    body: JSON.stringify(body),
  });
  return { status: res.status, json: (await res.json()) as Record<string, unknown> };
}

interface AuthResult {
  AccessToken?: string;
  IdToken?: string;
  RefreshToken?: string;
}

async function initiateAuth(body: Record<string, unknown>): Promise<{ status: number; json: Record<string, unknown>; result?: AuthResult }> {
  const res = await callCognito('InitiateAuth', body);
  return { ...res, result: res.json.AuthenticationResult as AuthResult | undefined };
}

async function passwordLogin(email: string, password = PASSWORD) {
  return initiateAuth({ AuthFlow: 'USER_PASSWORD_AUTH', ClientId: CLIENT_ID, AuthParameters: { USERNAME: email, PASSWORD: password } });
}

async function accessTokenFor(email: string): Promise<string> {
  const res = await passwordLogin(email);
  const token = res.result?.AccessToken;
  if (!token) throw new Error(`No access token for ${email}: ${JSON.stringify(res.json)}`);
  return token;
}

function decodePayload(token: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString('utf8')) as Record<string, unknown>;
}

async function createUser(attrs: Record<string, string> = {}): Promise<{ email: string; sub: string }> {
  const email = `new-${Math.random().toString(36).slice(2, 8)}@example.com`;
  const res = await callCognito('AdminCreateUser', {
    Username: email,
    UserAttributes: [{ Name: 'email', Value: email }, ...Object.entries(attrs).map(([Name, Value]) => ({ Name, Value }))],
    MessageAction: 'SUPPRESS',
  });
  expect(res.status).toBe(200);
  const attributes = (res.json.User as { Attributes: Array<{ Name: string; Value: string }> }).Attributes;
  return { email, sub: attributes.find((a) => a.Name === 'sub')!.Value };
}

function attrsOf(list: unknown): Record<string, string> {
  return Object.fromEntries(((list ?? []) as Array<{ Name: string; Value: string }>).map((a) => [a.Name, a.Value]));
}

/**
 * A token pair minted through the browser path: /oauth2/authorize with PKCE,
 * then /oauth2/token. The only path that lets a test choose the scope list.
 */
async function hostedUiLogin(opts: { scope?: string; selectedUser?: string } = {}) {
  const verifier = 'a'.repeat(64);
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const redirectUri = 'http://localhost:5173/auth/callback';

  const authorizeUrl = new URL(`${baseUrl}/oauth2/authorize`);
  authorizeUrl.searchParams.set('response_type', 'code');
  authorizeUrl.searchParams.set('client_id', CLIENT_ID);
  authorizeUrl.searchParams.set('redirect_uri', redirectUri);
  authorizeUrl.searchParams.set('state', 'state-123');
  authorizeUrl.searchParams.set('code_challenge', challenge);
  authorizeUrl.searchParams.set('code_challenge_method', 'S256');
  // An empty string is NOT the same request as an absent parameter: the
  // emulator falls back to its default only when the caller sends no scope.
  if (opts.scope) authorizeUrl.searchParams.set('scope', opts.scope);
  if (opts.selectedUser) authorizeUrl.searchParams.set('selected_user', opts.selectedUser);
  authorizeUrl.searchParams.set('continue', '1');

  const authorized = await fetch(authorizeUrl, { redirect: 'manual' });
  expect(authorized.status).toBe(302);
  const location = new URL(authorized.headers.get('location')!);
  expect(location.searchParams.get('state')).toBe('state-123');
  const code = location.searchParams.get('code')!;

  const exchange = (overrides: Record<string, string> = {}) => fetch(`${baseUrl}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: CLIENT_ID,
      redirect_uri: redirectUri,
      code_verifier: verifier,
      ...overrides,
    }),
  });

  return { code, exchange };
}

async function hostedUiTokens(opts: { scope?: string; selectedUser?: string } = {}) {
  const { exchange } = await hostedUiLogin(opts);
  const res = await exchange();
  expect(res.status).toBe(200);
  return (await res.json()) as { access_token: string; id_token: string; refresh_token: string; token_type: string };
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

describe('Cognito emulator: tokens', () => {
  it('signs tokens that verify against the published JWKS', async () => {
    const tokens = await hostedUiTokens();
    const jwks = (await (await fetch(`${baseUrl}/.well-known/jwks.json`)).json()) as { keys: Array<JsonWebKey & { kid: string }> };

    for (const token of [tokens.access_token, tokens.id_token]) {
      const [header, payload, signature] = token.split('.') as [string, string, string];
      const { kid, alg } = JSON.parse(Buffer.from(header, 'base64url').toString()) as { kid: string; alg: string };
      expect(alg).toBe('RS256');
      const jwk = jwks.keys.find((k) => k.kid === kid)!;
      const valid = verifySignature(
        'RSA-SHA256',
        Buffer.from(`${header}.${payload}`),
        createPublicKey({ key: jwk, format: 'jwk' }),
        Buffer.from(signature, 'base64url'),
      );
      expect(valid).toBe(true);
    }
  });

  it('names the request origin as issuer, matching the discovery document', async () => {
    const tokens = await hostedUiTokens();
    const discovery = (await (await fetch(`${baseUrl}/.well-known/openid-configuration`)).json()) as { issuer: string; jwks_uri: string };

    expect(decodePayload(tokens.id_token).iss).toBe(baseUrl);
    expect(discovery.issuer).toBe(baseUrl);
    expect(discovery.jwks_uri).toBe(`${baseUrl}/.well-known/jwks.json`);
  });

  it('puts custom attributes on the ID token and NOT on the access token, as Cognito does', async () => {
    const tokens = await hostedUiTokens({ selectedUser: 'admin-001' });

    const id = decodePayload(tokens.id_token);
    const access = decodePayload(tokens.access_token);
    expect(id['custom:tenantId']).toBe('tenant-a');
    expect(id.aud).toBe(CLIENT_ID);
    expect(id.email).toBe('admin@example.com');
    expect(id.token_use).toBe('id');
    expect(access['custom:tenantId']).toBeUndefined();
    expect(access.token_use).toBe('access');
    expect(access['cognito:groups']).toEqual(['Admin', 'Users']);
  });

  it('reports the real email_verified on the ID token', async () => {
    const tokens = await hostedUiTokens({ selectedUser: 'unverified-001' });

    expect(decodePayload(tokens.id_token).email_verified).toBe(false);
  });

  it('a group change reaches the very next token', async () => {
    expect(decodePayload(await accessTokenFor('user@example.com'))['cognito:groups']).toEqual(['Users']);

    await callCognito('AdminAddUserToGroup', { Username: 'user-001', GroupName: 'Admin' });
    expect(decodePayload(await accessTokenFor('user@example.com'))['cognito:groups']).toContain('Admin');

    await callCognito('AdminRemoveUserFromGroup', { Username: 'user-001', GroupName: 'Admin' });
    expect(decodePayload(await accessTokenFor('user@example.com'))['cognito:groups']).not.toContain('Admin');
  });
});

// ---------------------------------------------------------------------------
// Hosted UI
// ---------------------------------------------------------------------------

describe('Cognito emulator: hosted UI', () => {
  it('shows a user picker with a testId per primary group and per extra user', async () => {
    const url = new URL(`${baseUrl}/oauth2/authorize`);
    url.search = new URLSearchParams({
      response_type: 'code', client_id: CLIENT_ID, redirect_uri: 'http://localhost/cb', state: 's',
      code_challenge: 'c', code_challenge_method: 'S256',
    }).toString();

    const html = await (await fetch(url)).text();
    expect(html).toContain('data-testid="local-auth-continue-admin"');
    expect(html).toContain('data-testid="local-auth-continue-users"');
    expect(html).toContain('data-testid="local-auth-continue-user-mfa-001"');
  });

  it('selects a user by primary group name', async () => {
    const tokens = await hostedUiTokens({ selectedUser: 'Admin' });
    expect(decodePayload(tokens.access_token).sub).toBe('admin-001');
  });

  it.each([
    ['response_type', { response_type: 'token' }, 302],
    ['client_id', { client_id: 'wrong' }, 302],
    ['state', { state: '' }, 400],
    ['PKCE method', { code_challenge_method: 'plain' }, 400],
  ])('refuses a bad %s', async (_label, override, status) => {
    const params = {
      response_type: 'code', client_id: CLIENT_ID, redirect_uri: 'http://localhost/cb', state: 's',
      code_challenge: 'c', code_challenge_method: 'S256', continue: '1', ...override,
    };
    const res = await fetch(`${baseUrl}/oauth2/authorize?${new URLSearchParams(params)}`, { redirect: 'manual' });
    expect(res.status).toBe(status);
    if (status === 302) expect(res.headers.get('location')).toContain('/error?error=invalid_request');
  });

  it('returns a refresh token from the code exchange that REFRESH_TOKEN_AUTH accepts', async () => {
    const tokens = await hostedUiTokens();

    const refreshed = await initiateAuth({ AuthFlow: 'REFRESH_TOKEN_AUTH', ClientId: CLIENT_ID, AuthParameters: { REFRESH_TOKEN: tokens.refresh_token } });
    expect(refreshed.status).toBe(200);
    expect(refreshed.result?.AccessToken).toBeTruthy();
  });

  it('a code is single use and says so', async () => {
    const { exchange } = await hostedUiLogin();
    expect((await exchange()).status).toBe(200);

    const second = await exchange();
    expect(second.status).toBe(400);
    expect(((await second.json()) as { error_description: string }).error_description).toContain('unknown or already-redeemed');
  });

  it('refuses a PKCE verifier that does not match', async () => {
    const { exchange } = await hostedUiLogin();

    const res = await exchange({ code_verifier: 'b'.repeat(64) });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error_description: string }).error_description).toContain('PKCE verifier');
  });

  it('refuses a redirect_uri that differs from the authorize request', async () => {
    const { exchange } = await hostedUiLogin();

    const res = await exchange({ redirect_uri: 'http://evil.example/cb' });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error_description: string }).error_description).toContain('redirect_uri');
  });

  it('refuses an unknown client at the token endpoint', async () => {
    const { exchange } = await hostedUiLogin();
    expect((await exchange({ client_id: 'wrong' })).status).toBe(401);
  });

  it('refuses a grant type other than authorization_code', async () => {
    const { exchange } = await hostedUiLogin();
    const res = await exchange({ grant_type: 'client_credentials' });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe('unsupported_grant_type');
  });

  it('logout redirects to logout_uri', async () => {
    const res = await fetch(`${baseUrl}/logout?logout_uri=${encodeURIComponent('http://localhost:5173/')}`, { redirect: 'manual' });
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('http://localhost:5173/');
  });
});

// ---------------------------------------------------------------------------
// InitiateAuth
// ---------------------------------------------------------------------------

describe('Cognito emulator: InitiateAuth', () => {
  it('USER_PASSWORD_AUTH issues a refresh token usable to mint fresh tokens', async () => {
    const login = await passwordLogin('admin@example.com');
    expect(login.status).toBe(200);

    const refreshed = await initiateAuth({ AuthFlow: 'REFRESH_TOKEN_AUTH', ClientId: CLIENT_ID, AuthParameters: { REFRESH_TOKEN: login.result!.RefreshToken } });
    expect(refreshed.status).toBe(200);
    expect(refreshed.result?.AccessToken).toBeTruthy();
    expect(refreshed.result?.IdToken).toBeTruthy();
    // REFRESH_TOKEN_AUTH does not return a new refresh token (matches Cognito).
    expect(refreshed.result?.RefreshToken).toBeUndefined();
  });

  it('refuses a wrong password', async () => {
    const res = await passwordLogin('admin@example.com', 'WrongPassword1!');
    expect(res.status).toBe(400);
    expect(res.json.__type).toBe('NotAuthorizedException');
  });

  it('refuses a wrong client id', async () => {
    const res = await initiateAuth({ AuthFlow: 'USER_PASSWORD_AUTH', ClientId: 'wrong', AuthParameters: { USERNAME: 'admin@example.com', PASSWORD } });
    expect(res.json.__type).toBe('NotAuthorizedException');
  });

  it('refuses a missing password with InvalidParameterException', async () => {
    const res = await initiateAuth({ AuthFlow: 'USER_PASSWORD_AUTH', ClientId: CLIENT_ID, AuthParameters: { USERNAME: 'admin@example.com' } });
    expect(res.json.__type).toBe('InvalidParameterException');
  });

  it('refuses an unknown refresh token', async () => {
    const res = await initiateAuth({ AuthFlow: 'REFRESH_TOKEN_AUTH', ClientId: CLIENT_ID, AuthParameters: { REFRESH_TOKEN: 'bogus' } });
    expect(res.status).toBe(400);
    expect(res.json.__type).toBe('NotAuthorizedException');
  });

  it('refuses REFRESH_TOKEN_AUTH with no REFRESH_TOKEN', async () => {
    const res = await initiateAuth({ AuthFlow: 'REFRESH_TOKEN_AUTH', ClientId: CLIENT_ID, AuthParameters: {} });
    expect(res.json.__type).toBe('InvalidParameterException');
  });

  it('refuses an unsupported auth flow', async () => {
    const res = await initiateAuth({ AuthFlow: 'CUSTOM_AUTH', ClientId: CLIENT_ID, AuthParameters: {} });
    expect(res.json.__type).toBe('InvalidParameterException');
  });

  it('AdminUserGlobalSignOut revokes the refresh tokens', async () => {
    const login = await passwordLogin('user@example.com');
    await callCognito('AdminUserGlobalSignOut', { Username: 'user-001' });

    const refreshed = await initiateAuth({ AuthFlow: 'REFRESH_TOKEN_AUTH', ClientId: CLIENT_ID, AuthParameters: { REFRESH_TOKEN: login.result!.RefreshToken } });
    expect(refreshed.json.__type).toBe('NotAuthorizedException');
  });

  it('refuses an operation the emulator does not implement, by name', async () => {
    const res = await callCognito('AdminResetUserPassword', { Username: 'user-001' });
    expect(res.status).toBe(400);
    expect(res.json.__type).toBe('UnknownOperationException');
    expect(String(res.json.message)).toContain('AdminResetUserPassword');
  });
});

// ---------------------------------------------------------------------------
// Through the AWS SDK
// ---------------------------------------------------------------------------

describe('Cognito emulator through the AWS SDK', () => {
  it('InitiateAuth, AdminGetUser, ListUsers and AdminListGroupsForUser parse', async () => {
    const auth = await sdk.send(new InitiateAuthCommand({
      AuthFlow: 'USER_PASSWORD_AUTH',
      ClientId: CLIENT_ID,
      AuthParameters: { USERNAME: 'admin@example.com', PASSWORD },
    }));
    expect(auth.AuthenticationResult?.AccessToken).toBeTruthy();

    const got = await sdk.send(new AdminGetUserCommand({ UserPoolId: 'local', Username: 'admin-001' }));
    expect(got.UserStatus).toBe('CONFIRMED');
    expect(attrsOf(got.UserAttributes)).toMatchObject({ email: 'admin@example.com', given_name: 'Ada', family_name: 'Admin', 'custom:tenantId': 'tenant-a' });

    const listed = await sdk.send(new ListUsersCommand({ UserPoolId: 'local', Filter: 'email = "user@example.com"' }));
    expect(listed.Users?.map((u) => u.Username)).toEqual(['user-001']);

    const groups = await sdk.send(new AdminListGroupsForUserCommand({ UserPoolId: 'local', Username: 'admin-001' }));
    expect(groups.Groups?.map((g) => g.GroupName)).toEqual(['Admin', 'Users']);
  });

  it('refusals surface as the SDK\'s own exception classes', async () => {
    await expect(sdk.send(new InitiateAuthCommand({
      AuthFlow: 'USER_PASSWORD_AUTH',
      ClientId: CLIENT_ID,
      AuthParameters: { USERNAME: 'admin@example.com', PASSWORD: 'Wrong1!aaa' },
    }))).rejects.toBeInstanceOf(NotAuthorizedException);

    await expect(sdk.send(new AdminGetUserCommand({ UserPoolId: 'local', Username: 'nobody' })))
      .rejects.toBeInstanceOf(UserNotFoundException);
  });

  it('ListUsersInGroup pages through the members of one group, without case in the group name', async () => {
    const first = await sdk.send(new ListUsersInGroupCommand({ UserPoolId: 'local', GroupName: 'users', Limit: 4 }));
    expect(first.Users?.map((u) => u.Username)).toEqual(['admin-001', 'user-001', 'mfa-001', 'nomfa-001']);
    expect(first.Users?.[0]?.Attributes?.find((a) => a.Name === 'sub')?.Value).toBe('admin-001');
    expect(first.NextToken).toBeTruthy();

    const second = await sdk.send(new ListUsersInGroupCommand({ UserPoolId: 'local', GroupName: 'Users', Limit: 4, NextToken: first.NextToken }));
    expect(second.Users?.map((u) => u.Username)).toEqual(['badcode-001', 'unverified-001']);
    expect(second.NextToken).toBeUndefined();

    const admins = await sdk.send(new ListUsersInGroupCommand({ UserPoolId: 'local', GroupName: 'Admin' }));
    expect(admins.Users?.map((u) => u.Username)).toEqual(['admin-001']);
    const nobody = await sdk.send(new ListUsersInGroupCommand({ UserPoolId: 'local', GroupName: 'nobody-group' }));
    expect(nobody.Users).toEqual([]);
  });

  it('ListUsersInGroup refuses a token from another group and a Limit above 60', async () => {
    const first = await sdk.send(new ListUsersInGroupCommand({ UserPoolId: 'local', GroupName: 'Users', Limit: 1 }));
    await expect(sdk.send(new ListUsersInGroupCommand({ UserPoolId: 'local', GroupName: 'Admin', NextToken: first.NextToken })))
      .rejects.toBeInstanceOf(InvalidParameterException);
    await expect(sdk.send(new ListUsersInGroupCommand({ UserPoolId: 'local', GroupName: 'Users', NextToken: 'garbage' })))
      .rejects.toBeInstanceOf(InvalidParameterException);
    await expect(sdk.send(new ListUsersInGroupCommand({ UserPoolId: 'local', GroupName: 'Users', Limit: 61 })))
      .rejects.toBeInstanceOf(InvalidParameterException);
  });

  it('AdminCreateUser returns FORCE_CHANGE_PASSWORD and stores custom attributes', async () => {
    const created = await sdk.send(new AdminCreateUserCommand({
      UserPoolId: 'local',
      Username: 'invitee@example.com',
      UserAttributes: [{ Name: 'email', Value: 'invitee@example.com' }, { Name: 'custom:tenantId', Value: 'tenant-b' }],
      MessageAction: 'SUPPRESS',
    }));

    expect(created.User?.UserStatus).toBe('FORCE_CHANGE_PASSWORD');
    expect(attrsOf(created.User?.Attributes)['custom:tenantId']).toBe('tenant-b');
    expect(running.emulator.getUser('invitee@example.com')?.customAttributes).toEqual({ tenantId: 'tenant-b' });
  });
});

// ---------------------------------------------------------------------------
// User administration
// ---------------------------------------------------------------------------

describe('Cognito emulator: user administration', () => {
  it('rejects AdminCreateUser when the email format is invalid', async () => {
    const res = await callCognito('AdminCreateUser', {
      Username: 'not-an-email',
      UserAttributes: [{ Name: 'email', Value: 'not-an-email' }],
    });
    expect(res.status).toBe(400);
    expect(res.json.__type).toBe('InvalidParameterException');
  });

  it('rejects a duplicate email with UsernameExistsException', async () => {
    const res = await callCognito('AdminCreateUser', {
      Username: 'admin@example.com',
      UserAttributes: [{ Name: 'email', Value: 'admin@example.com' }],
    });
    expect(res.json.__type).toBe('UsernameExistsException');
  });

  it('rejects a temporary password that breaks the policy', async () => {
    const res = await callCognito('AdminCreateUser', {
      Username: 'weak@example.com',
      UserAttributes: [{ Name: 'email', Value: 'weak@example.com' }],
      TemporaryPassword: 'weak',
    });
    expect(res.json.__type).toBe('InvalidPasswordException');
  });

  it.each([
    ['no symbol', 'Password1'],
    ['no upper', 'password1!'],
    ['no lower', 'PASSWORD1!'],
    ['no number', 'Password!'],
    ['too short', 'Aa1!'],
  ])('rejects AdminSetUserPassword for %s', async (_label, password) => {
    const { email } = await createUser();

    const set = await callCognito('AdminSetUserPassword', { Username: email, Password: password, Permanent: true });
    expect(set.status).toBe(400);
    expect(set.json.__type).toBe('InvalidPasswordException');
    expect(String(set.json.message)).toMatch(/Password does not conform to policy/);
  });

  it('a permanent AdminSetUserPassword confirms the account; a temporary one does not', async () => {
    const { email, sub } = await createUser();

    await callCognito('AdminSetUserPassword', { Username: email, Password: 'Temporary1!', Permanent: false });
    expect((await callCognito('AdminGetUser', { Username: sub })).json.UserStatus).toBe('FORCE_CHANGE_PASSWORD');

    await callCognito('AdminSetUserPassword', { Username: email, Password: 'Permanent1!', Permanent: true });
    expect((await callCognito('AdminGetUser', { Username: sub })).json.UserStatus).toBe('CONFIRMED');
    expect((await passwordLogin(email, 'Permanent1!')).status).toBe(200);
  });

  it('AdminCreateUser without name attributes yields a user with NO given_name/family_name', async () => {
    const { sub } = await createUser();

    const attrs = attrsOf((await callCognito('AdminGetUser', { Username: sub })).json.UserAttributes);
    expect(attrs).not.toHaveProperty('given_name');
    expect(attrs).not.toHaveProperty('family_name');
  });

  it('AdminCreateUser puts the new user in newUserGroups only', async () => {
    const { sub } = await createUser();
    expect((await callCognito('AdminListGroupsForUser', { Username: sub })).json.Groups).toEqual([]);
  });

  it('AdminUpdateUserAttributes stores the name, email_verified and custom attributes', async () => {
    const { sub } = await createUser({ email_verified: 'false' });

    const update = await callCognito('AdminUpdateUserAttributes', {
      Username: sub,
      UserAttributes: [
        { Name: 'given_name', Value: 'Wendy' },
        { Name: 'family_name', Value: 'Example' },
        { Name: 'email_verified', Value: 'true' },
        { Name: 'custom:tenantId', Value: 'tenant-c' },
      ],
    });
    expect(update.status).toBe(200);

    const attrs = attrsOf((await callCognito('AdminGetUser', { Username: sub })).json.UserAttributes);
    expect(attrs).toMatchObject({ given_name: 'Wendy', family_name: 'Example', email_verified: 'true', 'custom:tenantId': 'tenant-c' });
  });

  it('AdminUpdateUserAttributes changes one name part and keeps the other', async () => {
    await callCognito('AdminUpdateUserAttributes', { Username: 'user-001', UserAttributes: [{ Name: 'family_name', Value: 'Renamed' }] });

    expect(running.emulator.getUser('user-001')?.name).toBe('Uma Renamed');
  });

  it.each(['AdminUpdateUserAttributes', 'AdminGetUser', 'AdminDeleteUser', 'AdminSetUserPassword', 'AdminListGroupsForUser', 'AdminUserGlobalSignOut', 'AdminDisableUser', 'AdminEnableUser'])(
    '%s refuses an unknown user with UserNotFoundException',
    async (action) => {
      const res = await callCognito(action, { Username: 'no-such-user', Password: PASSWORD, UserAttributes: [] });
      expect(res.status).toBe(400);
      expect(res.json.__type).toBe('UserNotFoundException');
    },
  );

  it('AdminAddUserToGroup does not add a group twice', async () => {
    await callCognito('AdminAddUserToGroup', { Username: 'user-001', GroupName: 'users' });
    expect(running.emulator.getUser('user-001')?.groups).toEqual(['Users']);
  });

  it('AdminDeleteUser removes the user, so the email can be used again', async () => {
    const { email } = await createUser();

    expect((await callCognito('AdminDeleteUser', { Username: email })).status).toBe(200);
    expect(running.emulator.getUser(email)).toBeNull();

    const recreate = await callCognito('AdminCreateUser', { Username: email, UserAttributes: [{ Name: 'email', Value: email }], MessageAction: 'SUPPRESS' });
    expect(recreate.status).toBe(200);
  });

  it('reset puts the seed users back', async () => {
    await createUser();
    await callCognito('AdminDeleteUser', { Username: 'admin-001' });

    const res = await fetch(`${baseUrl}/__local/reset`, { method: 'POST' });
    expect(res.status).toBe(204);
    expect(running.emulator.listUsers().map((u) => u.userId)).toEqual(SEED_USERS.map((u) => u.userId));
  });
});

describe('Cognito emulator: ListUsers', () => {
  it('APPLIES an email Filter instead of returning the whole pool', async () => {
    const { email } = await createUser();

    const matched = await callCognito('ListUsers', { Filter: `email = "${email}"` });
    expect(matched.json.Users).toHaveLength(1);

    const unmatched = await callCognito('ListUsers', { Filter: 'email = "nobody@example.com"' });
    expect(unmatched.json.Users).toHaveLength(0);
  });

  it('applies a prefix Filter', async () => {
    const res = await callCognito('ListUsers', { Filter: 'email ^= "adm"' });
    expect((res.json.Users as Array<{ Username: string }>).map((u) => u.Username)).toEqual(['admin-001']);
  });

  it('filters on user status', async () => {
    await createUser();
    const res = await callCognito('ListUsers', { Filter: 'cognito:user_status = "FORCE_CHANGE_PASSWORD"' });
    expect(res.json.Users).toHaveLength(1);
  });

  it('rejects a Filter on a custom attribute, as Cognito does', async () => {
    const res = await callCognito('ListUsers', { Filter: 'custom:tenantId = "tenant-a"' });
    expect(res.status).toBe(400);
    expect(res.json.__type).toBe('InvalidParameterException');
  });

  it('returns the whole pool with no Filter, and honours Limit', async () => {
    expect((await callCognito('ListUsers', {})).json.Users).toHaveLength(SEED_USERS.length);
    expect((await callCognito('ListUsers', { Limit: 1 })).json.Users).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Software token MFA and scopes
// ---------------------------------------------------------------------------

describe('Cognito emulator: software token MFA enrolment', () => {
  it('associate, verify, then enable — and GetUser and /__local/mfa-state report it', async () => {
    const accessToken = await accessTokenFor('mfa@example.com');

    const associate = await callCognito('AssociateSoftwareToken', { AccessToken: accessToken });
    expect(typeof associate.json.SecretCode).toBe('string');

    const verify = await callCognito('VerifySoftwareToken', { AccessToken: accessToken, UserCode: '123456' });
    expect(verify.json.Status).toBe('SUCCESS');

    await callCognito('SetUserMFAPreference', { AccessToken: accessToken, SoftwareTokenMfaSettings: { Enabled: true, PreferredMfa: true } });

    expect((await callCognito('GetUser', { AccessToken: accessToken })).json.UserMFASettingList).toContain('SOFTWARE_TOKEN_MFA');
    const state = (await (await fetch(`${baseUrl}/__local/mfa-state?email=mfa@example.com`)).json()) as { enabled: boolean };
    expect(state.enabled).toBe(true);
  });

  it.each([
    ['all zeroes', '000000'],
    ['not six digits', '12ab'],
  ])('VerifySoftwareToken rejects a wrong code (%s)', async (_label, badCode) => {
    const accessToken = await accessTokenFor('badcode@example.com');
    await callCognito('AssociateSoftwareToken', { AccessToken: accessToken });

    const verify = await callCognito('VerifySoftwareToken', { AccessToken: accessToken, UserCode: badCode });
    expect(verify.status).toBe(400);
    expect(verify.json.__type).toBe('EnableSoftwareTokenMFAException');
  });

  it('VerifySoftwareToken with no prior association fails with ResourceNotFoundException', async () => {
    const accessToken = await accessTokenFor('nomfa@example.com');

    const verify = await callCognito('VerifySoftwareToken', { AccessToken: accessToken, UserCode: '123456' });
    expect(verify.json.__type).toBe('ResourceNotFoundException');
  });
});

describe('Cognito emulator: self-service calls require the Cognito scope', () => {
  const SELF_SERVICE_ACTIONS = [
    ['GetUser', {}],
    ['AssociateSoftwareToken', {}],
    ['VerifySoftwareToken', { UserCode: '123456' }],
    ['SetUserMFAPreference', { SoftwareTokenMfaSettings: { Enabled: true, PreferredMfa: true } }],
  ] as const;

  it.each(SELF_SERVICE_ACTIONS)('%s refuses a token granted only openid/email/profile', async (action, extraBody) => {
    const { access_token } = await hostedUiTokens({ scope: 'openid email profile' });

    const res = await callCognito(action, { AccessToken: access_token, ...extraBody });
    expect(res.status).toBe(400);
    expect(res.json.__type).toBe('NotAuthorizedException');
    expect(res.json.message).toBe('Access Token does not have required scopes');
  });

  it.each(SELF_SERVICE_ACTIONS)('%s accepts a token granted aws.cognito.signin.user.admin', async (action, extraBody) => {
    const { access_token } = await hostedUiTokens({ scope: 'openid email profile aws.cognito.signin.user.admin' });
    // VerifySoftwareToken needs a secret first; the others do not mind one.
    await callCognito('AssociateSoftwareToken', { AccessToken: access_token });

    const res = await callCognito(action, { AccessToken: access_token, ...extraBody });
    expect(res.status).toBe(200);
  });

  it('an unreadable token is refused as an invalid token, not a scope failure', async () => {
    const res = await callCognito('GetUser', { AccessToken: 'not.a.token' });
    expect(res.json.message).toBe('Invalid Access Token');
  });

  it('an ID token is not accepted where an access token is required', async () => {
    const { id_token } = await hostedUiTokens();
    const res = await callCognito('GetUser', { AccessToken: id_token });
    expect(res.json.message).toBe('Invalid Access Token');
  });

  it('USER_PASSWORD_AUTH and a scope-less authorize both grant the self-service scope', async () => {
    const fromPassword = decodePayload(await accessTokenFor('user@example.com'));
    const fromHostedUi = decodePayload((await hostedUiTokens()).access_token);

    expect(String(fromPassword.scope).split(' ')).toContain('aws.cognito.signin.user.admin');
    expect(String(fromHostedUi.scope).split(' ')).toContain('aws.cognito.signin.user.admin');
  });

  it('the discovery document advertises the self-service scope', async () => {
    const body = (await (await fetch(`${baseUrl}/.well-known/openid-configuration`)).json()) as { scopes_supported: string[] };
    expect(body.scopes_supported).toContain('aws.cognito.signin.user.admin');
  });
});

// ---------------------------------------------------------------------------
// Forgotten password
// ---------------------------------------------------------------------------

describe('Cognito emulator: ForgotPassword', () => {
  /** A fresh account in the state each case needs, so no case depends on another. */
  async function seedUser(opts: { emailVerified?: 'true' | 'false'; activate?: boolean }): Promise<string> {
    const { email } = await createUser(opts.emailVerified ? { email_verified: opts.emailVerified } : {});
    if (opts.activate) {
      const set = await callCognito('AdminSetUserPassword', { Username: email, Password: PASSWORD, Permanent: true });
      expect(set.status).toBe(200);
    }
    return email;
  }

  async function readStoredCode(email: string): Promise<string | null> {
    const res = await fetch(`${baseUrl}/__local/forgot-password-code?email=${encodeURIComponent(email)}`);
    return ((await res.json()) as { code: string | null }).code;
  }

  const forgot = (email: string, clientId = CLIENT_ID) => callCognito('ForgotPassword', { ClientId: clientId, Username: email });
  const confirm = (email: string, code: string | null, password = 'NewPassword1!', clientId = CLIENT_ID) =>
    callCognito('ConfirmForgotPassword', { ClientId: clientId, Username: email, ConfirmationCode: code, Password: password });

  it('issues a six-digit code and masked delivery details for a verified, activated account', async () => {
    const email = await seedUser({ emailVerified: 'true', activate: true });

    const res = await forgot(email);
    expect(res.status).toBe(200);
    const delivery = res.json.CodeDeliveryDetails as Record<string, string>;
    expect(delivery).toMatchObject({ DeliveryMedium: 'EMAIL', AttributeName: 'email' });
    expect(delivery.Destination).not.toContain(email);
    expect(await readStoredCode(email)).toMatch(/^\d{6}$/);
  });

  it('refuses a wrong client id, and stores no code', async () => {
    const email = await seedUser({ emailVerified: 'true', activate: true });

    const res = await forgot(email, 'other-client');
    expect(res.json.__type).toBe('NotAuthorizedException');
    expect(await readStoredCode(email)).toBeNull();
  });

  it('refuses an unknown user with UserNotFoundException', async () => {
    const res = await forgot('nobody@example.com');
    expect(res.json).toMatchObject({ __type: 'UserNotFoundException', message: 'User does not exist.' });
  });

  it('refuses a never-activated account with NotAuthorizedException', async () => {
    const res = await forgot(await seedUser({ emailVerified: 'true' }));
    expect(res.json).toMatchObject({ __type: 'NotAuthorizedException', message: 'User password cannot be reset in the current state.' });
  });

  it('refuses an account with no verified address with InvalidParameterException', async () => {
    const res = await forgot(await seedUser({ emailVerified: 'false', activate: true }));
    expect(res.json.__type).toBe('InvalidParameterException');
    expect(String(res.json.message)).toContain('no registered/verified email');
  });

  it('replaces the stored code on a second request, so only the newest works', async () => {
    const email = await seedUser({ emailVerified: 'true', activate: true });
    await forgot(email);
    const first = await readStoredCode(email);
    await forgot(email);
    const second = await readStoredCode(email);

    // If the two codes collide by chance the stale confirm succeeds, so assert
    // on the refusal only when they differ.
    if (first !== second) {
      expect((await confirm(email, first)).json.__type).toBe('CodeMismatchException');
    }
    expect((await confirm(email, second)).status).toBe(200);
  });

  it('sets the password, so the new one signs in and the old one does not, and the code is spent', async () => {
    const email = await seedUser({ emailVerified: 'true', activate: true });
    await forgot(email);

    expect((await confirm(email, await readStoredCode(email))).status).toBe(200);
    expect((await passwordLogin(email, 'NewPassword1!')).status).toBe(200);
    expect((await passwordLogin(email, PASSWORD)).json.__type).toBe('NotAuthorizedException');
    expect(await readStoredCode(email)).toBeNull();
  });

  it('revokes the refresh tokens of a session opened before the reset', async () => {
    const email = await seedUser({ emailVerified: 'true', activate: true });
    const signedIn = await passwordLogin(email);
    await forgot(email);
    await confirm(email, await readStoredCode(email));

    const refreshed = await initiateAuth({ AuthFlow: 'REFRESH_TOKEN_AUTH', ClientId: CLIENT_ID, AuthParameters: { REFRESH_TOKEN: signedIn.result!.RefreshToken } });
    expect(refreshed.json.__type).toBe('NotAuthorizedException');
  });

  it('ConfirmForgotPassword refuses a wrong client id', async () => {
    const email = await seedUser({ emailVerified: 'true', activate: true });
    await forgot(email);

    expect((await confirm(email, await readStoredCode(email), 'NewPassword1!', 'other-client')).json.__type).toBe('NotAuthorizedException');
  });

  it('refuses a wrong code with CodeMismatchException', async () => {
    const email = await seedUser({ emailVerified: 'true', activate: true });
    await forgot(email);
    const code = await readStoredCode(email);

    const res = await confirm(email, code === '000000' ? '111111' : '000000');
    expect(res.json).toMatchObject({ __type: 'CodeMismatchException', message: 'Invalid verification code provided, please try again.' });
  });

  it('answers an account with no code, and an unknown user, as a code mismatch', async () => {
    const email = await seedUser({ emailVerified: 'true', activate: true });

    expect((await confirm(email, '123456')).json.__type).toBe('CodeMismatchException');
    expect((await confirm('nobody@example.com', '123456')).json.__type).toBe('CodeMismatchException');
  });

  it('refuses an expired code with ExpiredCodeException', async () => {
    const email = await seedUser({ emailVerified: 'true', activate: true });
    await forgot(email);
    const code = await readStoredCode(email);

    const expire = await fetch(`${baseUrl}/__local/expire-forgot-password-code?email=${encodeURIComponent(email)}`, { method: 'POST' });
    expect(expire.status).toBe(200);

    expect((await confirm(email, code)).json).toMatchObject({
      __type: 'ExpiredCodeException',
      message: 'Invalid code provided, please request a code again.',
    });
  });

  it('refuses a password that breaks the policy, and keeps the code', async () => {
    const email = await seedUser({ emailVerified: 'true', activate: true });
    await forgot(email);
    const code = await readStoredCode(email);

    const res = await confirm(email, code, 'short');
    expect(res.json.__type).toBe('InvalidPasswordException');
    expect(await readStoredCode(email)).toBe(code);
  });

  it('checks the code before the password policy', async () => {
    const email = await seedUser({ emailVerified: 'true', activate: true });
    await forgot(email);
    const code = await readStoredCode(email);

    expect((await confirm(email, code === '000000' ? '111111' : '000000', 'short')).json.__type).toBe('CodeMismatchException');
  });

  it('/__local/expire-forgot-password-code answers 404 when there is no code to expire', async () => {
    const res = await fetch(`${baseUrl}/__local/expire-forgot-password-code?email=nobody@example.com`, { method: 'POST' });
    expect(res.status).toBe(404);
  });
});

describe('Cognito emulator helpers', () => {
  it('masks an email the way Cognito does', () => {
    expect(maskEmailDestination('wendy@example.org')).toBe('w***@e***.org');
    expect(maskEmailDestination('x@localhost')).toBe('x***@l***');
    expect(maskEmailDestination('nonsense')).toBe('***');
  });

  it('accepts a password that meets the default policy', () => {
    expect(validateCognitoDefaultPasswordPolicy('Password1!')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// User lifecycle: disable/enable, invitations, NEW_PASSWORD_REQUIRED
// ---------------------------------------------------------------------------

const POOL = 'local';

/** A user created through the SDK with a known temporary password, still FORCE_CHANGE_PASSWORD. */
async function createInvitedUser(temporaryPassword = 'Temporary1!'): Promise<{ email: string; sub: string }> {
  const email = `invited-${Math.random().toString(36).slice(2, 8)}@example.com`;
  const created = await sdk.send(new AdminCreateUserCommand({
    UserPoolId: POOL,
    Username: email,
    UserAttributes: [{ Name: 'email', Value: email }, { Name: 'email_verified', Value: 'true' }],
    TemporaryPassword: temporaryPassword,
    MessageAction: 'SUPPRESS',
  }));
  return { email, sub: created.User!.Username! };
}

/** The authorize request parameters for the hosted UI, with the user already picked. */
function authorizeParams(selectedUser: string): Record<string, string> {
  return {
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: 'http://localhost:5173/auth/callback',
    state: 'state-123',
    code_challenge: createHash('sha256').update('a'.repeat(64)).digest('base64url'),
    code_challenge_method: 'S256',
    selected_user: selectedUser,
    continue: '1',
  };
}

describe('Cognito emulator: AdminDisableUser and AdminEnableUser', () => {
  it('a disabled user reads Enabled: false and cannot sign in; enabling restores both', async () => {
    await sdk.send(new AdminDisableUserCommand({ UserPoolId: POOL, Username: 'user-001' }));

    expect((await sdk.send(new AdminGetUserCommand({ UserPoolId: POOL, Username: 'user-001' }))).Enabled).toBe(false);
    const listed = await sdk.send(new ListUsersCommand({ UserPoolId: POOL, Filter: 'username = "user-001"' }));
    expect(listed.Users?.[0]?.Enabled).toBe(false);
    expect(running.emulator.getUser('user-001')?.enabled).toBe(false);

    const refused = sdk.send(new InitiateAuthCommand({
      AuthFlow: 'USER_PASSWORD_AUTH', ClientId: CLIENT_ID, AuthParameters: { USERNAME: 'user@example.com', PASSWORD },
    }));
    await expect(refused).rejects.toBeInstanceOf(NotAuthorizedException);
    await expect(refused).rejects.toThrow('User is disabled.');

    await sdk.send(new AdminEnableUserCommand({ UserPoolId: POOL, Username: 'user-001' }));
    expect((await sdk.send(new AdminGetUserCommand({ UserPoolId: POOL, Username: 'user-001' }))).Enabled).toBe(true);
    expect((await passwordLogin('user@example.com')).status).toBe(200);
  });

  it('a wrong password for a disabled user is still a wrong password', async () => {
    await sdk.send(new AdminDisableUserCommand({ UserPoolId: POOL, Username: 'user-001' }));

    const res = await passwordLogin('user@example.com', 'WrongPassword1!');
    expect(res.json).toMatchObject({ __type: 'NotAuthorizedException', message: 'Incorrect username or password.' });
  });

  it('accepts the email as Username, as Cognito does for an email-username pool', async () => {
    await sdk.send(new AdminDisableUserCommand({ UserPoolId: POOL, Username: 'user@example.com' }));
    expect(running.emulator.getUser('user-001')?.enabled).toBe(false);

    await sdk.send(new AdminEnableUserCommand({ UserPoolId: POOL, Username: 'user@example.com' }));
    expect(running.emulator.getUser('user-001')?.enabled).toBe(true);
  });

  it('revokes the refresh token and the access token, and enabling does not bring them back', async () => {
    const login = await passwordLogin('user@example.com');
    await sdk.send(new AdminDisableUserCommand({ UserPoolId: POOL, Username: 'user-001' }));
    await sdk.send(new AdminEnableUserCommand({ UserPoolId: POOL, Username: 'user-001' }));

    const refreshed = await initiateAuth({ AuthFlow: 'REFRESH_TOKEN_AUTH', ClientId: CLIENT_ID, AuthParameters: { REFRESH_TOKEN: login.result!.RefreshToken } });
    expect(refreshed.json.__type).toBe('NotAuthorizedException');

    const getUser = sdk.send(new GetUserCommand({ AccessToken: login.result!.AccessToken }));
    await expect(getUser).rejects.toBeInstanceOf(NotAuthorizedException);
    await expect(getUser).rejects.toThrow('Access Token has been revoked');

    // A token minted after re-enabling works.
    expect((await callCognito('GetUser', { AccessToken: await accessTokenFor('user@example.com') })).status).toBe(200);
  });

  it('AdminUserGlobalSignOut revokes the access token for Cognito API calls too', async () => {
    const accessToken = await accessTokenFor('user@example.com');
    await callCognito('AdminUserGlobalSignOut', { Username: 'user-001' });

    expect((await callCognito('GetUser', { AccessToken: accessToken })).json.message).toBe('Access Token has been revoked');
  });

  it('the hosted UI refuses a disabled user and issues no code', async () => {
    await sdk.send(new AdminDisableUserCommand({ UserPoolId: POOL, Username: 'user-001' }));

    const res = await fetch(`${baseUrl}/oauth2/authorize?${new URLSearchParams(authorizeParams('user-001'))}`, { redirect: 'manual' });
    expect(res.status).toBe(400);
    const html = await res.text();
    expect(html).toContain('User is disabled.');
    expect(html).toContain('data-testid="local-auth-error"');
  });

  it('ListUsers filters on status = "Enabled" / "Disabled", case-sensitively', async () => {
    await sdk.send(new AdminDisableUserCommand({ UserPoolId: POOL, Username: 'user-001' }));

    const disabled = await sdk.send(new ListUsersCommand({ UserPoolId: POOL, Filter: 'status = "Disabled"' }));
    expect(disabled.Users?.map((u) => u.Username)).toEqual(['user-001']);
    const enabled = await sdk.send(new ListUsersCommand({ UserPoolId: POOL, Filter: 'status = "Enabled"' }));
    expect(enabled.Users).toHaveLength(SEED_USERS.length - 1);
    expect((await sdk.send(new ListUsersCommand({ UserPoolId: POOL, Filter: 'status = "disabled"' }))).Users).toHaveLength(0);
  });

  it('a seed user can start disabled', () => {
    const emulator = createCognitoEmulator({ users: [{ userId: 'u', email: 'u@example.com', name: '', groups: [], enabled: false }] });
    expect(emulator.getUser('u')?.enabled).toBe(false);
  });
});

describe('Cognito emulator: AdminCreateUser invitations', () => {
  const readInvitation = async (email: string) =>
    ((await (await fetch(`${baseUrl}/__local/invitation?email=${encodeURIComponent(email)}`)).json()) as {
      invitation: { temporaryPassword: string; deliveryMediums: string[] } | null;
    }).invitation;

  it('SUPPRESS sends no invitation and, with no TemporaryPassword, leaves no password anyone knows', async () => {
    const created = await sdk.send(new AdminCreateUserCommand({
      UserPoolId: POOL, Username: 'quiet@example.com', UserAttributes: [{ Name: 'email', Value: 'quiet@example.com' }], MessageAction: 'SUPPRESS',
    }));

    expect(created.User).toMatchObject({ UserStatus: 'FORCE_CHANGE_PASSWORD', Enabled: true });
    expect(created.User?.UserCreateDate).toBeInstanceOf(Date);
    expect(await readInvitation('quiet@example.com')).toBeNull();
    expect(running.emulator.getInvitation('quiet@example.com')).toBeNull();
    expect((await passwordLogin('quiet@example.com', PASSWORD)).json.__type).toBe('NotAuthorizedException');
  });

  it('DesiredDeliveryMediums EMAIL records the invitation with a generated temporary password that meets the policy', async () => {
    await sdk.send(new AdminCreateUserCommand({
      UserPoolId: POOL, Username: 'invitee2@example.com', UserAttributes: [{ Name: 'email', Value: 'invitee2@example.com' }], DesiredDeliveryMediums: ['EMAIL'],
    }));

    const invitation = await readInvitation('invitee2@example.com');
    expect(invitation?.deliveryMediums).toEqual(['EMAIL']);
    expect(validateCognitoDefaultPasswordPolicy(invitation!.temporaryPassword)).toBeNull();
    expect(running.emulator.getInvitation('invitee2@example.com')?.temporaryPassword).toBe(invitation!.temporaryPassword);

    // The temporary password works, and leads to the challenge.
    const login = await passwordLogin('invitee2@example.com', invitation!.temporaryPassword);
    expect(login.json.ChallengeName).toBe('NEW_PASSWORD_REQUIRED');
  });

  it('an invitation carries the TemporaryPassword the caller chose', async () => {
    await callCognito('AdminCreateUser', {
      Username: 'chosen@example.com', UserAttributes: [{ Name: 'email', Value: 'chosen@example.com' }], TemporaryPassword: 'Chosen123!', DesiredDeliveryMediums: ['EMAIL'],
    });
    expect((await readInvitation('chosen@example.com'))?.temporaryPassword).toBe('Chosen123!');
  });

  it.each([
    ['the default SMS medium', {}],
    ['an explicit SMS medium', { DesiredDeliveryMediums: ['SMS'] }],
  ])('refuses %s, which the emulator cannot deliver without a phone number', async (_label, extra) => {
    const res = await callCognito('AdminCreateUser', { Username: 'sms@example.com', UserAttributes: [{ Name: 'email', Value: 'sms@example.com' }], ...extra });
    expect(res.json.__type).toBe('InvalidParameterException');
    expect(String(res.json.message)).toContain('SMS');
    expect(running.emulator.getUser('sms@example.com')).toBeNull();
  });

  it.each([
    ['MessageAction', { MessageAction: 'SHOUT' }],
    ['DesiredDeliveryMediums', { DesiredDeliveryMediums: ['PIGEON'] }],
  ])('refuses an invalid %s', async (_label, extra) => {
    const res = await callCognito('AdminCreateUser', { Username: 'bad@example.com', UserAttributes: [{ Name: 'email', Value: 'bad@example.com' }], ...extra });
    expect(res.json.__type).toBe('InvalidParameterException');
  });

  it('RESEND issues a new temporary password and the old one stops working', async () => {
    await callCognito('AdminCreateUser', {
      Username: 'resend@example.com', UserAttributes: [{ Name: 'email', Value: 'resend@example.com' }], TemporaryPassword: 'FirstTemp1!', DesiredDeliveryMediums: ['EMAIL'],
    });

    const resent = await sdk.send(new AdminCreateUserCommand({ UserPoolId: POOL, Username: 'resend@example.com', MessageAction: 'RESEND', DesiredDeliveryMediums: ['EMAIL'] }));
    expect(resent.User?.UserStatus).toBe('FORCE_CHANGE_PASSWORD');
    expect(running.emulator.listUsers().filter((u) => u.email === 'resend@example.com')).toHaveLength(1);

    const invitation = await readInvitation('resend@example.com');
    expect(invitation?.temporaryPassword).not.toBe('FirstTemp1!');
    expect((await passwordLogin('resend@example.com', 'FirstTemp1!')).json.__type).toBe('NotAuthorizedException');
    expect((await passwordLogin('resend@example.com', invitation!.temporaryPassword)).json.ChallengeName).toBe('NEW_PASSWORD_REQUIRED');
  });

  it('RESEND refuses an unknown user and a user who has already set a password', async () => {
    await expect(sdk.send(new AdminCreateUserCommand({ UserPoolId: POOL, Username: 'ghost@example.com', MessageAction: 'RESEND', DesiredDeliveryMediums: ['EMAIL'] })))
      .rejects.toBeInstanceOf(UserNotFoundException);

    const confirmed = sdk.send(new AdminCreateUserCommand({ UserPoolId: POOL, Username: 'user@example.com', MessageAction: 'RESEND', DesiredDeliveryMediums: ['EMAIL'] }));
    await expect(confirmed).rejects.toBeInstanceOf(UnsupportedUserStateException);
    await expect(confirmed).rejects.toThrow('status is not FORCE_CHANGE_PASSWORD');
  });

  it('UserLastModifiedDate moves on a change; UserCreateDate does not', async () => {
    const { sub } = await createInvitedUser();
    const before = await sdk.send(new AdminGetUserCommand({ UserPoolId: POOL, Username: sub }));
    await new Promise((resolve) => setTimeout(resolve, 1100));

    await sdk.send(new AdminUpdateUserAttributesCommand({ UserPoolId: POOL, Username: sub, UserAttributes: [{ Name: 'given_name', Value: 'Later' }] }));
    const after = await sdk.send(new AdminGetUserCommand({ UserPoolId: POOL, Username: sub }));

    expect(after.UserCreateDate?.getTime()).toBe(before.UserCreateDate?.getTime());
    expect(after.UserLastModifiedDate!.getTime()).toBeGreaterThan(before.UserLastModifiedDate!.getTime());
  });

  it('a user created by AdminCreateUser joins groups by email or sub, and the groups reach the token', async () => {
    const { email, sub } = await createInvitedUser();
    await sdk.send(new AdminAddUserToGroupCommand({ UserPoolId: POOL, Username: email, GroupName: 'Admin' }));
    await sdk.send(new AdminAddUserToGroupCommand({ UserPoolId: POOL, Username: sub, GroupName: 'Users' }));

    const groups = await sdk.send(new AdminListGroupsForUserCommand({ UserPoolId: POOL, Username: email }));
    expect(groups.Groups?.map((g) => g.GroupName)).toEqual(['Admin', 'Users']);

    await sdk.send(new AdminSetUserPasswordCommand({ UserPoolId: POOL, Username: email, Password: 'Permanent1!', Permanent: true }));
    const id = decodePayload((await passwordLogin(email, 'Permanent1!')).result!.IdToken!);
    expect(id['cognito:groups']).toEqual(['Admin', 'Users']);
  });
});

describe('Cognito emulator: NEW_PASSWORD_REQUIRED', () => {
  it('InitiateAuth for a FORCE_CHANGE_PASSWORD user returns the challenge and no tokens', async () => {
    const { email, sub } = await createInvitedUser();

    const auth = await sdk.send(new InitiateAuthCommand({ AuthFlow: 'USER_PASSWORD_AUTH', ClientId: CLIENT_ID, AuthParameters: { USERNAME: email, PASSWORD: 'Temporary1!' } }));
    expect(auth.AuthenticationResult).toBeUndefined();
    expect(auth.ChallengeName).toBe('NEW_PASSWORD_REQUIRED');
    expect(auth.Session).toBeTruthy();
    expect(auth.ChallengeParameters?.USER_ID_FOR_SRP).toBe(sub);
    expect(JSON.parse(auth.ChallengeParameters!.userAttributes!)).toMatchObject({ email, email_verified: 'true' });
    expect(auth.ChallengeParameters?.requiredAttributes).toBe('[]');
  });

  it('RespondToAuthChallenge enforces the policy, then confirms the user and issues tokens', async () => {
    const { email, sub } = await createInvitedUser();
    const auth = await sdk.send(new InitiateAuthCommand({ AuthFlow: 'USER_PASSWORD_AUTH', ClientId: CLIENT_ID, AuthParameters: { USERNAME: email, PASSWORD: 'Temporary1!' } }));

    const weak = sdk.send(new RespondToAuthChallengeCommand({
      ClientId: CLIENT_ID, ChallengeName: 'NEW_PASSWORD_REQUIRED', Session: auth.Session, ChallengeResponses: { USERNAME: email, NEW_PASSWORD: 'short' },
    }));
    await expect(weak).rejects.toBeInstanceOf(InvalidPasswordException);

    const done = await sdk.send(new RespondToAuthChallengeCommand({
      ClientId: CLIENT_ID,
      ChallengeName: 'NEW_PASSWORD_REQUIRED',
      Session: auth.Session,
      ChallengeResponses: { USERNAME: email, NEW_PASSWORD: 'Chosen123!', 'userAttributes.given_name': 'Ivy' },
    }));
    expect(done.AuthenticationResult?.AccessToken).toBeTruthy();
    expect(decodePayload(done.AuthenticationResult!.IdToken!).sub).toBe(sub);

    const got = await sdk.send(new AdminGetUserCommand({ UserPoolId: POOL, Username: sub }));
    expect(got.UserStatus).toBe('CONFIRMED');
    expect(attrsOf(got.UserAttributes).given_name).toBe('Ivy');
    expect((await passwordLogin(email, 'Chosen123!')).result?.AccessToken).toBeTruthy();
  });

  it('a challenge session is single use', async () => {
    const { email } = await createInvitedUser();
    const auth = await sdk.send(new InitiateAuthCommand({ AuthFlow: 'USER_PASSWORD_AUTH', ClientId: CLIENT_ID, AuthParameters: { USERNAME: email, PASSWORD: 'Temporary1!' } }));
    const respond = () => sdk.send(new RespondToAuthChallengeCommand({
      ClientId: CLIENT_ID, ChallengeName: 'NEW_PASSWORD_REQUIRED', Session: auth.Session, ChallengeResponses: { USERNAME: email, NEW_PASSWORD: 'Chosen123!' },
    }));

    await respond();
    await expect(respond()).rejects.toBeInstanceOf(NotAuthorizedException);
  });

  it('refuses an unknown session, a wrong client, and a challenge the emulator does not model', async () => {
    const bogus = sdk.send(new RespondToAuthChallengeCommand({
      ClientId: CLIENT_ID, ChallengeName: 'NEW_PASSWORD_REQUIRED', Session: 'bogus', ChallengeResponses: { USERNAME: 'user@example.com', NEW_PASSWORD: 'Chosen123!' },
    }));
    await expect(bogus).rejects.toBeInstanceOf(NotAuthorizedException);
    await expect(bogus).rejects.toThrow('Invalid session for the user.');

    expect((await callCognito('RespondToAuthChallenge', { ClientId: 'wrong', ChallengeName: 'NEW_PASSWORD_REQUIRED', Session: 'x', ChallengeResponses: {} })).json.__type)
      .toBe('NotAuthorizedException');
    expect((await callCognito('RespondToAuthChallenge', { ClientId: CLIENT_ID, ChallengeName: 'SMS_MFA', Session: 'x', ChallengeResponses: {} })).json.__type)
      .toBe('InvalidParameterException');
  });

  it('refuses a userAttributes.* the emulator does not store', async () => {
    const { email } = await createInvitedUser();
    const auth = await passwordLogin(email, 'Temporary1!');

    const res = await callCognito('RespondToAuthChallenge', {
      ClientId: CLIENT_ID,
      ChallengeName: 'NEW_PASSWORD_REQUIRED',
      Session: auth.json.Session,
      ChallengeResponses: { USERNAME: email, NEW_PASSWORD: 'Chosen123!', 'userAttributes.phone_number': '+447700900000' },
    });
    expect(res.json.__type).toBe('InvalidParameterException');
    expect(String(res.json.message)).toContain('phone_number');
  });

  it('the hosted UI asks a FORCE_CHANGE_PASSWORD user for a new password before issuing a code', async () => {
    const { email, sub } = await createInvitedUser();

    const picked = await fetch(`${baseUrl}/oauth2/authorize?${new URLSearchParams(authorizeParams(sub))}`, { redirect: 'manual' });
    expect(picked.status).toBe(200);
    const page = await picked.text();
    expect(page).toContain('data-testid="local-auth-new-password"');
    expect(page).toContain('method="post"');

    const post = (newPassword: string) => fetch(`${baseUrl}/oauth2/authorize`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ ...authorizeParams(sub), new_password: newPassword }),
    });

    const weak = await post('short');
    expect(weak.status).toBe(400);
    expect(await weak.text()).toContain('Password does not conform to policy: Password not long enough');
    expect(running.emulator.getUser(email)?.forceChangePassword).toBe(true);

    const accepted = await post('Chosen123!');
    expect(accepted.status).toBe(302);
    const location = new URL(accepted.headers.get('location')!);
    expect(location.searchParams.get('code')).toBeTruthy();
    expect(running.emulator.getUser(email)?.forceChangePassword).toBe(false);
    expect((await passwordLogin(email, 'Chosen123!')).status).toBe(200);
  });
});

describe('Cognito emulator: AdminSetUserPassword and the password policy', () => {
  it('a temporary password puts a CONFIRMED user back into FORCE_CHANGE_PASSWORD', async () => {
    await sdk.send(new AdminSetUserPasswordCommand({ UserPoolId: POOL, Username: 'user@example.com', Password: 'Temporary1!', Permanent: false }));

    expect((await sdk.send(new AdminGetUserCommand({ UserPoolId: POOL, Username: 'user-001' }))).UserStatus).toBe('FORCE_CHANGE_PASSWORD');
    expect((await passwordLogin('user@example.com', 'Temporary1!')).json.ChallengeName).toBe('NEW_PASSWORD_REQUIRED');
  });

  it('omitting Permanent sets a temporary password, as Permanent defaults to false', async () => {
    await callCognito('AdminSetUserPassword', { Username: 'user-001', Password: 'Temporary1!' });
    expect(running.emulator.getUser('user-001')?.forceChangePassword).toBe(true);
  });

  it('refuses with Cognito\'s own wording', async () => {
    const res = sdk.send(new AdminSetUserPasswordCommand({ UserPoolId: POOL, Username: 'user-001', Password: 'Sh0rt!', Permanent: true }));
    await expect(res).rejects.toBeInstanceOf(InvalidPasswordException);
    await expect(res).rejects.toThrow('Password does not conform to policy: Password not long enough');
  });

  it('enforces the policy the emulator was started with', async () => {
    const custom = await startCognitoEmulator({
      port: 0,
      host: '127.0.0.1',
      clientId: CLIENT_ID,
      users: SEED_USERS,
      passwordPolicy: { minimumLength: 12, requireSymbols: false },
    });
    const client = new CognitoIdentityProviderClient({ endpoint: custom.url, region: 'us-east-1', credentials: { accessKeyId: 'test', secretAccessKey: 'test' } });
    try {
      await expect(client.send(new AdminSetUserPasswordCommand({ UserPoolId: POOL, Username: 'user-001', Password: 'Password1!', Permanent: true })))
        .rejects.toThrow('Password not long enough');
      await client.send(new AdminSetUserPasswordCommand({ UserPoolId: POOL, Username: 'user-001', Password: 'Password1abc', Permanent: true }));
      expect(custom.emulator.getUser('user-001')?.forceChangePassword).toBe(false);
    } finally {
      client.destroy();
      await custom.close();
    }
  });

  it('refuses a policy Cognito itself would not accept', () => {
    expect(() => createCognitoEmulator({ passwordPolicy: { minimumLength: 5 } })).toThrow(/minimumLength/);
    expect(() => createCognitoEmulator({ passwordPolicy: { minimumLength: 100 } })).toThrow(/minimumLength/);
  });

  it('validateCognitoPasswordPolicy names the first broken rule', () => {
    expect(COGNITO_DEFAULT_PASSWORD_POLICY).toEqual({ minimumLength: 8, requireLowercase: true, requireUppercase: true, requireNumbers: true, requireSymbols: true });
    expect(validateCognitoPasswordPolicy('abc', { minimumLength: 6 })).toBe('Password not long enough');
    expect(validateCognitoPasswordPolicy('abcdefgh', { requireUppercase: false, requireNumbers: false, requireSymbols: false })).toBeNull();
    expect(validateCognitoPasswordPolicy('abcdefgh', {})).toBe('Password must have uppercase characters');
  });
});

describe('Cognito emulator: ListUsers pagination and AttributesToGet', () => {
  it('pages through the pool with Limit and PaginationToken, with no duplicates', async () => {
    const seen: string[] = [];
    let token: string | undefined;
    let pages = 0;
    do {
      const page = await sdk.send(new ListUsersCommand({ UserPoolId: POOL, Limit: 4, PaginationToken: token }));
      seen.push(...(page.Users ?? []).map((u) => u.Username!));
      token = page.PaginationToken;
      pages += 1;
    } while (token);

    expect(pages).toBe(2);
    expect(seen).toEqual(SEED_USERS.map((u) => u.userId));
  });

  it('returns no PaginationToken when the page holds everything', async () => {
    const page = await sdk.send(new ListUsersCommand({ UserPoolId: POOL }));
    expect(page.PaginationToken).toBeUndefined();
  });

  it('refuses a Limit above 60 and a PaginationToken it did not issue', async () => {
    await expect(sdk.send(new ListUsersCommand({ UserPoolId: POOL, Limit: 61 }))).rejects.toBeInstanceOf(InvalidParameterException);
    await expect(sdk.send(new ListUsersCommand({ UserPoolId: POOL, PaginationToken: 'bogus' }))).rejects.toBeInstanceOf(InvalidParameterException);
  });

  it('a PaginationToken only continues the query it came from', async () => {
    const page = await sdk.send(new ListUsersCommand({ UserPoolId: POOL, Limit: 1 }));
    expect(page.PaginationToken).toBeTruthy();
    await expect(sdk.send(new ListUsersCommand({ UserPoolId: POOL, Limit: 1, Filter: 'email ^= "u"', PaginationToken: page.PaginationToken })))
      .rejects.toBeInstanceOf(InvalidParameterException);
  });

  it('AttributesToGet returns only the named attributes', async () => {
    const res = await sdk.send(new ListUsersCommand({ UserPoolId: POOL, AttributesToGet: ['email'], Filter: 'username = "admin-001"' }));
    expect(res.Users?.[0]?.Attributes).toEqual([{ Name: 'email', Value: 'admin@example.com' }]);
  });
});
