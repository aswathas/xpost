# xpost — post to X (Twitter) from the terminal

Same shape as `postiee` (your LinkedIn CLI): one command, credentials stored
locally, a local history log, nothing written anywhere else.

```
xpost doctor                  who am I, are the credentials good
xpost "hello from the shell"  publish
xpost --file post.md          publish a file
xpost --file post.md --image shot.png
xpost --reply-to <id> "and the reply"
xpost delete <id>             take a post back down
xpost history                 what this tool posted
```

---

## 1. Get an X developer app

1. Sign in at **https://console.x.com** with the X account that will post.
2. Accept the developer agreement and create a **Project**, then an **App**
   inside it (an app must belong to a project — this is the step people miss).
3. App settings → **User authentication settings**:
   - App permissions: **Read and write** (add *Read and direct messages* only
     if you need DM endpoints).
   - App type: **Web App, Confidential** if you want a client secret, or
     **Web App, Public** if you want pure PKCE with no secret.
   - Callback URI: `http://localhost:8788/callback`
   - Website URL: anything, e.g. `http://localhost:8788`.
4. Keys and tokens → **API Key and Token** → copy the **API key** and
   **API secret** (shown once).
5. Keys and tokens → **Access Token and Secret** → generate with
   **Access Level: Read and write** → copy the **access token** and
   **access token secret** (shown once). This is the *user context* pair — an
   app-only token will post as nobody.

## 2. Choose an auth mode

### OAuth 1.0a — fastest (recommended for text posts)

Four strings, no browser, no callback server. Paste them in:

```bash
cd C:\Users\aswat\xpost
node xpost.mjs init \
  --api-key <API_KEY> \
  --api-secret <API_SECRET> \
  --access-token <USER_ACCESS_TOKEN> \
  --access-token-secret <USER_ACCESS_TOKEN_SECRET>
```

### OAuth 2.0 + PKCE — needed for media and for refresh tokens

Use it when you want image uploads, a refresh token that survives an expiry,
or fine-grained scopes.

```bash
node xpost.mjs init --mode oauth2 --client-id <CLIENT_ID> --client-secret <CLIENT_SECRET>
```

The tool prints an authorize URL. Open it, sign in as the posting account,
approve the scopes, and the callback is captured automatically. The token is
stored with its refresh token and re-authenticates itself.

Requested scopes: `tweet.read tweet.write users.read media.write offline.access`.

> `media.write` is a separate scope from `tweet.write`. A token issued without
> it can publish text and gets a **403 the moment you attach a file**.

## 3. Check it

```bash
node xpost.mjs doctor
```

```
✓ xpost — doctor
  mode          oauth1
  posting as    @aswathas (123456789)
✓ X API reachable.
```

## 4. Post

```bash
node xpost.mjs post "181 skill folders on my machine. No way to tell which were actually on.

So I built the control room that reads the files Claude Code already writes.

https://aswathas.github.io/captain-code/"

node xpost.mjs post --file C:\Users\aswat\Projects\captain-code\social\tweet.md
node xpost.mjs post --file post.md --image p1.png --image p2.png
node xpost.mjs post --reply-to 1900000000000000000 "and the follow-up"
```

Add it to `PATH` so you can just type `xpost`:

```powershell
# PowerShell profile
$env:Path += ";C:\Users\aswat\xpost"
```

or drop `xpost.cmd` next to it:

```bat
@echo off
node "%~dp0xpost.mjs" %*
```

## 5. What it costs

X is **pay-per-use** now — no monthly tier needed for posting:

| Action | Cost |
|---|---|
| Post: Create | $0.015 |
| Post: Create **with a URL** | $0.200 |
| Post: Create (reply) | $0.010 |
| Media upload | priced per request |

A post with a link is **13× the price of a post without one**. If you are
posting a lot of links, keep the link in a reply and post the value in the
first tweet — that also reads better, because the first line is what shows up
before "…see more".

New accounts get a one-time $20 credit for adding a payment card, plus up to
a $50 match on the first auto-recharge.

## 6. Limits

| Endpoint | Limit |
|---|---|
| `POST /2/tweets` | 100 per 15 min per user, 10,000 per 24 h per app |
| media upload | 500 per 15 min per user |

## 7. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `403` on every post | pay-per-use app with no credits, or a missing scope | check console.x.com → billing; re-authorise with `media.write` |
| `403` on upload but text works | token lacks `media.write` | re-run `xpost init --mode oauth2` and approve again |
| `401` | expired token | OAuth 2 refreshes itself; OAuth 1 tokens do not — regenerate them |
| `429` | rate limit | 100 posts / 15 min; wait |
| Post works, images do not | `media.write` not granted | re-authorise |
| Nothing in `history` | posting from the web UI, not this tool | the log only records what xpost sent |

## Security

- Credentials live in `~/.config/xpost/config.json` (mode 600 on unix).
- The tool never prints a secret — only the post id and URL.
- `credentials.json`-style files are never read or uploaded.
- The OAuth 2 callback server binds to `localhost` and closes after one use.

## License

MIT.
