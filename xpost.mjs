/**
 * xpost — post to X (Twitter) from the terminal.
 *
 * Two auth modes, because X's developer console hands them out differently:
 *
 *   oauth1  API key + API secret + access token + access token secret.
 *           Fastest path: paste four strings, done. Signs requests with
 *           HMAC-SHA1 (OAuth 1.0a user context).
 *
 *   oauth2  OAuth 2.0 authorization code + PKCE, with a refresh token.
 *           Needed for the v2 media endpoints when they insist on a
 *           `media.write` scope, and it survives a password change.
 *
 * Credentials live in ~/.config/xpost/config.json (chmod 600 on unix).
 * Nothing is ever printed except the post id and the URL.
 */
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import http from 'node:http';
import { spawn } from 'node:child_process';

const CONFIG_DIR = path.join(os.homedir(), '.config', 'xpost');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');
const HISTORY_FILE = path.join(CONFIG_DIR, 'history.jsonl');

const API = 'https://api.x.com';
const AUTH = 'https://twitter.com/i/oauth2/authorize';
const TOKEN = 'https://api.x.com/2/oauth2/token';
const CALLBACK_PORT = 8788;
const CALLBACK = `http://localhost:${CALLBACK_PORT}/callback`;

/* ------------------------------------------------------------------ utils */

const c = {
  bold: (s) => `\u001b[1m${s}\u001b[0m`,
  dim: (s) => `\u001b[2m${s}\u001b[0m`,
  green: (s) => `\u001b[32m${s}\u001b[0m`,
  yellow: (s) => `\u001b[33m${s}\u001b[0m`,
  red: (s) => `\u001b[31m${s}\u001b[0m`,
  cyan: (s) => `\u001b[36m${s}\u001b[0m`,
};

const ok = (s) => console.log(`${c.green('✓')} ${s}`);
const warn = (s) => console.log(`${c.yellow('!')} ${s}`);
const fail = (s) => {
  console.error(`${c.red('✗')} ${s}`);
  process.exit(1);
};
const info = (s) => console.log(`${c.dim(s)}`);

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const [key, inline] = a.slice(2).split('=');
      if (inline !== undefined) args[key] = inline;
      else if (argv[i + 1] && !argv[i + 1].startsWith('--')) args[key] = argv[++i];
      else args[key] = true;
    } else if (a.startsWith('-') && a.length === 2) {
      const key = a.slice(1);
      if (argv[i + 1] && !argv[i + 1].startsWith('-')) args[key] = argv[++i];
      else args[key] = true;
    } else args._.push(a);
  }
  return args;
}

const b64url = (buf) =>
  Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/* ---------------------------------------------------------------- config */

function readConfig() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  } catch {
    return null;
  }
}

function writeConfig(config) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), { mode: 0o600 });
  try {
    fs.chmodSync(CONFIG_FILE, 0o600);
  } catch {
    /* windows: no unix modes */
  }
}

/* ------------------------------------------------------------------ auth */

/**
 * Parse a query string into decoded key/value pairs.
 *
 * X's own documentation says to "collect the raw values" — i.e. the decoded
 * values — and then percent-encode each key and value once to build the
 * parameter string, which is then percent-encoded once more for the base
 * string.
 */
function queryPairs(url) {
  const query = url.includes('?') ? url.slice(url.indexOf('?') + 1) : '';
  if (!query) return [];
  return [...new URLSearchParams(query).entries()];
}

function oauth1Header(method, url, pairs, cfg, overrides = {}) {
  const parsed = new URL(url);
  const oauth = {
    oauth_consumer_key: cfg.api_key,
    oauth_nonce: overrides.nonce || crypto.randomBytes(16).toString('hex'),
    oauth_signature_method: 'HMAC-SHA1',
    oauth_timestamp: overrides.timestamp || Math.floor(Date.now() / 1000).toString(),
    oauth_token: cfg.access_token,
    oauth_version: '1.0',
  };

  // The base string holds the request parameters and every oauth_* parameter
  // except oauth_signature itself.
  const allPairs = [...pairs, ...Object.entries(oauth)];
  allPairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const paramString = allPairs.map(([k, v]) => `${encodeRFC3986(k)}=${encodeRFC3986(v)}`).join('&');

  const base = [
    method.toUpperCase(),
    encodeRFC3986(`${parsed.protocol}//${parsed.host}${parsed.pathname}`),
    encodeRFC3986(paramString),
  ].join('&');

  const signingKey = `${encodeRFC3986(cfg.api_secret)}&${encodeRFC3986(cfg.access_token_secret)}`;
  const signature = crypto.createHmac('sha1', signingKey).update(base).digest('base64');
  oauth.oauth_signature = signature;

  const header = Object.keys(oauth)
    .sort()
    .map((k) => `${encodeRFC3986(k)}="${encodeRFC3986(oauth[k])}"`)
    .join(', ');

  return `OAuth ${header}`;
}

function encodeRFC3986(str) {
  return encodeURIComponent(str).replace(/[!'()*]/g, (ch) => `%${ch.charCodeAt(0).toString(16).toUpperCase()}`);
}

/** Returns a valid user access token, refreshing an OAuth 2 token if needed. */
async function getToken(cfg) {
  if (cfg.mode === 'oauth1') return { type: 'oauth1', cfg };
  if (!cfg.access_token) fail('No access token. Run: xpost init');

  const expiresInMs = (cfg.expires_at || 0) - Date.now();
  if (expiresInMs > 60_000) return { type: 'bearer', token: cfg.access_token };

  if (!cfg.refresh_token) {
    fail('The access token expired and there is no refresh token. Run: xpost init --mode oauth2');
  }

  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: cfg.refresh_token,
    client_id: cfg.client_id,
  });
  if (cfg.client_secret) body.set('client_secret', cfg.client_secret);

  const res = await fetch(TOKEN, { method: 'POST', body });
  const data = await res.json();
  if (!res.ok) fail(`Token refresh failed (${res.status}): ${data.error_description || data.error || 'unknown'}`);

  cfg.access_token = data.access_token;
  cfg.expires_at = Date.now() + (data.expires_in || 7200) * 1000;
  if (data.refresh_token) cfg.refresh_token = data.refresh_token;
  writeConfig(cfg);
  return { type: 'bearer', token: cfg.access_token };
}

async function apiFetch(method, url, { cfg, body, headers = {} } = {}) {
  const auth = await getToken(cfg);
  const h = { ...headers };

  if (auth.type === 'bearer') {
    h.Authorization = `Bearer ${auth.token}`;
  } else {
    h.Authorization = oauth1Header(method, url, queryPairs(url), auth.cfg);
  }

  let payload = body;
  if (body && !(body instanceof FormData)) {
    h['Content-Type'] = h['Content-Type'] || 'application/json';
    payload = JSON.stringify(body);
  }

  const res = await fetch(url, { method, headers: h, body: payload });
  const text = await res.text();
  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { raw: text };
  }
  if (!res.ok) {
    const detail = data.detail || data.title || data.error || text || res.statusText;
    fail(`${method} ${new URL(url).pathname} → ${res.status}: ${detail}`);
  }
  return data;
}

/* ----------------------------------------------------------------- media */

/**
 * Chunked image upload: INIT → APPEND → FINALIZE on /2/media/upload.
 * The v1.1 upload.twitter.com endpoint was deprecated in March 2025.
 */
async function uploadImage(cfg, filePath) {
  const bytes = await fsp.readFile(filePath);
  const ext = path.extname(filePath).toLowerCase();
  const mediaType =
    ext === '.png' ? 'image/png' : ext === '.gif' ? 'image/gif' : ext === '.webp' ? 'image/webp' : 'image/jpeg';

  const initForm = new FormData();
  initForm.set('command', 'INIT');
  initForm.set('media_type', mediaType);
  initForm.set('total_bytes', String(bytes.length));
  initForm.set('media_category', 'tweet_image');

  const init = await apiFetch('POST', `${API}/2/media/upload`, { cfg, body: initForm });
  const mediaId = init?.data?.id;
  if (!mediaId) fail(`Media INIT returned no id: ${JSON.stringify(init)}`);

  const CHUNK = 4 * 1024 * 1024;
  for (let index = 0; index * CHUNK < bytes.length; index += 1) {
    const slice = bytes.subarray(index * CHUNK, (index + 1) * CHUNK);
    const form = new FormData();
    form.set('command', 'APPEND');
    form.set('media_id', mediaId);
    form.set('segment_index', String(index));
    form.set('media', new Blob([slice], { type: mediaType }), path.basename(filePath));
    await apiFetch('POST', `${API}/2/media/upload/${mediaId}/append`, { cfg, body: form });
  }

  const doneForm = new FormData();
  doneForm.set('command', 'FINALIZE');
  doneForm.set('media_id', mediaId);
  const final = await apiFetch('POST', `${API}/2/media/upload/${mediaId}/finalize`, { cfg, body: doneForm });

  return final?.data?.id || mediaId;
}

/* ------------------------------------------------------------------ init */

async function initOauth2(cfg) {
  const verifier = b64url(crypto.randomBytes(32));
  const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
  const state = b64url(crypto.randomBytes(16));

  const url =
    `${AUTH}?response_type=code` +
    `&client_id=${encodeURIComponent(cfg.client_id)}` +
    `&redirect_uri=${encodeURIComponent(CALLBACK)}` +
    `&scope=${encodeURIComponent('tweet.read tweet.write users.read media.write offline.access')}` +
    `&code_challenge=${challenge}&code_challenge_method=S256&state=${state}`;

  console.log('');
  console.log(c.bold('  Open this URL, sign in as the posting account, approve the scopes:'));
  console.log('');
  console.log(`  ${c.cyan(url)}`);
  console.log('');
  console.log(c.dim(`  Waiting for the callback on ${CALLBACK} …`));

  const code = await new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const current = new URL(req.url, CALLBACK);
      if (current.pathname !== '/callback') {
        res.writeHead(404).end('not found');
        return;
      }
      const got = current.searchParams.get('code');
      const gotState = current.searchParams.get('state');
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(
        `<html><body style="font-family:sans-serif;padding:40px"><h2>${got ? 'Authorized.' : 'Failed.'}</h2>` +
          `<p>You can close this tab and go back to the terminal.</p></body></html>`
      );
      server.close();
      if (!got) reject(new Error('No code in the callback'));
      else if (gotState !== state) reject(new Error('State mismatch — did not accept the callback'));
      else resolve(got);
    });
    server.listen(CALLBACK_PORT, () => {});
    server.on('error', (err) => reject(err));
  });

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: CALLBACK,
    client_id: cfg.client_id,
    code_verifier: verifier,
  });
  if (cfg.client_secret) body.set('client_secret', cfg.client_secret);

  const res = await fetch(TOKEN, { method: 'POST', body });
  const data = await res.json();
  if (!res.ok) fail(`Token exchange failed: ${data.error_description || data.error}`);

  cfg.mode = 'oauth2';
  cfg.access_token = data.access_token;
  cfg.refresh_token = data.refresh_token;
  cfg.expires_at = Date.now() + (data.expires_in || 7200) * 1000;
  writeConfig(cfg);
  ok('OAuth 2.0 user token stored.');
}

/* ---------------------------------------------------------------- history */

function recordHistory(entry) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.appendFileSync(HISTORY_FILE, `${JSON.stringify(entry)}\n`);
}

function readHistory() {
  try {
    return fs
      .readFileSync(HISTORY_FILE, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line))
      .reverse();
  } catch {
    return [];
  }
}

/* --------------------------------------------------------------- commands */

async function cmdInit(args) {
  const cfg = readConfig() || { mode: 'oauth1' };

  if (args['client-id']) cfg.client_id = args['client-id'];
  if (args['client-secret']) cfg.client_secret = args['client-secret'];
  if (args['api-key']) cfg.api_key = args['api-key'];
  if (args['api-secret']) cfg.api_secret = args['api-secret'];
  if (args['access-token']) cfg.access_token = args['access-token'];
  if (args['access-token-secret']) cfg.access_token_secret = args['access-token-secret'];

  const mode = args.mode || cfg.mode || 'oauth1';

  if (mode === 'oauth2') {
    if (!cfg.client_id) fail('oauth2 needs a client id. Pass --client-id or set it first.');
    await initOauth2(cfg);
    return;
  }

  const missing = ['api_key', 'api_secret', 'access_token', 'access_token_secret'].filter((k) => !cfg[k]);
  if (missing.length) {
    fail(
      `Missing for OAuth 1.0a: ${missing.join(', ')}\n` +
        '  Get them from console.x.com → your app → Keys and Tokens → "Access Token and Secret" (user context).'
    );
  }
  cfg.mode = 'oauth1';
  writeConfig(cfg);
  ok('OAuth 1.0a user credentials stored.');
}

async function cmdDoctor() {
  const cfg = readConfig();
  if (!cfg) {
    console.log('');
    warn('No credentials yet. Run: xpost init');
    console.log('');
    info('  Fastest path  : OAuth 1.0a — console.x.com → app → Keys and Tokens → user access token');
    info('  Media + refresh: OAuth 2.0 PKCE — xpost init --mode oauth2 --client-id <id>');
    console.log('');
    return;
  }

  console.log('');
  console.log(c.bold('xpost — doctor'));
  console.log(c.dim('─'.repeat(52)));
  console.log(`  mode          ${cfg.mode || 'oauth1'}`);
  console.log(`  config        ${CONFIG_FILE}`);
  if (cfg.expires_at) {
    const left = Math.round((cfg.expires_at - Date.now()) / 1000);
    console.log(`  token         ${left > 0 ? `valid for ${left}s` : 'expired (will refresh)'}`);
  }

  try {
    const me = await apiFetch('GET', `${API}/2/users/me`, { cfg });
    console.log(`  posting as    @${me?.data?.username} (${me?.data?.id})`);
    ok('X API reachable.');
  } catch {
    /* apiFetch already exits */
  }

  console.log('');
  info('  Cost: $0.015 per post, $0.20 per post containing a URL, media endpoints priced separately.');
  console.log('');
}

async function cmdPost(args) {
  const cfg = readConfig();
  if (!cfg) fail('No credentials yet. Run: xpost init');

  let text;
  if (args.file) text = fs.readFileSync(args.file, 'utf8').trim();
  else if (args._.length) text = args._.join(' ').trim();
  else fail('Give me text: xpost "hello"  or  xpost --file post.md');

  const images = [];
  const rawImages = args.image ? (Array.isArray(args.image) ? args.image : [args.image]) : [];
  for (const img of rawImages) images.push(...String(img).split(',').map((s) => s.trim()).filter(Boolean));

  if (text.length > 280) warn(`Text is ${text.length} characters — X allows 280.`);
  if (images.length > 4) fail('X allows up to 4 images per post.');

  const body = { text };
  if (images.length) {
    const mediaIds = [];
    for (const img of images) {
      if (!fs.existsSync(img)) fail(`No such file: ${img}`);
      info(`  uploading ${path.basename(img)} …`);
      mediaIds.push(await uploadImage(cfg, img));
    }
    body.media = { media_ids: mediaIds };
  }
  if (args['reply-to']) body.reply = { in_reply_to_tweet_id: String(args['reply-to']) };

  if (args['dry-run']) {
    console.log(JSON.stringify(body, null, 2));
    info('Dry run — nothing sent.');
    return;
  }

  const res = await apiFetch('POST', `${API}/2/tweets`, { cfg, body });
  const id = res?.data?.id;
  recordHistory({ id, text, at: new Date().toISOString(), images: images.length });
  console.log('');
  ok(`Posted → https://x.com/i/status/${id}`);
  console.log('');
}

async function cmdDelete(args) {
  const cfg = readConfig();
  if (!cfg) fail('No credentials yet. Run: xpost init');
  const id = args._[0] || args.id;
  if (!id) fail('Give me the post id: xpost delete <id>');
  await apiFetch('DELETE', `${API}/2/tweets/${id}`, { cfg });
  ok(`Deleted ${id}`);
}

function cmdHistory() {
  const rows = readHistory();
  if (!rows.length) {
    warn('No posts recorded yet.');
    return;
  }
  for (const row of rows.slice(0, 20)) {
    console.log(`${row.at}  ${row.id}  ${row.text.replace(/\s+/g, ' ').slice(0, 90)}`);
  }
}

/* --------------------------------------------------------------- selftest */

/**
 * Verifies the OAuth 1.0a signing against the worked example published in
 * Twitter's own API documentation. If the signature matches the documented
 * value, the base string, the percent-encoding and the HMAC are all correct.
 */
function cmdSelftest() {
  const cfg = {
    api_key: 'xvz1evFS4wEEPTGEFPHBog',
    api_secret: 'kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw',
    access_token: '370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb',
    access_token_secret: 'LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE',
  };
  const url = 'https://api.x.com/1.1/statuses/update.json?include_entities=true';
  // X's published example: POST /1.1/statuses/update.json?include_entities=true
  // with the body
  //   status=Hello%20Ladies%20%2b%20Gentlemen%2c%20a%20signed%20OAuth%20request%21
  // The documented parameter table lists the decoded values, which is what the
  // signature is built from.
  const pairs = [
    ['include_entities', 'true'],
    ['status', 'Hello Ladies + Gentlemen, a signed OAuth request!'],
  ];
  const header = oauth1Header('POST', url, pairs, cfg, {
    nonce: 'kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg',
    timestamp: '1318622958',
  });

  const expected = 'Ls93hJiZbQ3akF3HF3x1Bz8%2FzU4%3D';
  const got = header.match(/oauth_signature="([^"]+)"/)?.[1];

  console.log('');
  console.log(c.bold('xpost — oauth1 signing selftest'));
  console.log(c.dim('  vector: Twitter API docs, "Creating a signature" example'));
  console.log(`  expected  ${expected}`);
  console.log(`  got       ${got}`);
  console.log('');
  if (got === expected) {
    ok('Signature matches the published vector.');
  } else {
    fail('Signature does not match — the OAuth 1.0a signing is wrong.');
  }
}

/* ------------------------------------------------------------------ main */

const HELP = `
${c.bold('xpost')} — post to X from the terminal

  ${c.bold('xpost init')} [flags]        store credentials
      --mode oauth1|oauth2              auth mode (default oauth1)
      --api-key <key>                   OAuth 1.0a API key
      --api-secret <secret>             OAuth 1.0a API secret
      --access-token <token>            OAuth 1.0a user access token
      --access-token-secret <secret>    OAuth 1.0a user access token secret
      --client-id <id>                  OAuth 2.0 client id
      --client-secret <secret>          OAuth 2.0 client secret

  ${c.bold('xpost doctor')}                 check credentials and who you post as
  ${c.bold('xpost post')} "<text>"          publish
      --file <path>                       publish the body of a file
      --image <path>                      attach an image (repeat up to 4 times)
      --reply-to <id>                    reply to a post id
      --dry-run                           print the request, send nothing
  ${c.bold('xpost delete')} <id>            delete a post
  ${c.bold('xpost history')}                what this tool posted
`;

const COMMANDS = {
  init: cmdInit,
  doctor: cmdDoctor,
  post: cmdPost,
  delete: cmdDelete,
  history: cmdHistory,
  selftest: cmdSelftest,
};

const argv = process.argv.slice(2);
const command = argv[0];
const args = parseArgs(argv.slice(1));

if (!command || args.help || command === 'help') {
  console.log(HELP);
  process.exit(0);
}

const fn = COMMANDS[command];
if (!fn) {
  fail(`Unknown command "${command}". Try: xpost help`);
}

Promise.resolve(fn(args)).catch((err) => {
  console.error(`${c.red('✗')} ${err?.message || err}`);
  process.exit(1);
});
