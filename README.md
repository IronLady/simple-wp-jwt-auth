# JWT Auth Pro Extensions

Best-practice security extensions for **[JWT Authentication for WP-API](https://wordpress.org/plugins/jwt-authentication-for-wp-rest-api/)** (the Tmeister free plugin). Adds what the free plugin lacks — **without forking or editing it**. The base plugin stays pristine and independently updatable; this add-on hooks into its existing filters and registers its own endpoints.

## Why

The free base plugin is **stateless-only**: a single access token, **7-day** lifetime, no refresh, no revocation, no logout, no rate limiting. A leaked token is valid for a week with no kill switch, and `/token` is brute-forceable. Those exact gaps are this plugin's feature list.

## What it adds

| Mechanism | How |
|-----------|-----|
| Short-lived access tokens (15 min, was 7 days) | `jwt_auth_expire` filter |
| `jti` + `typ` claims on access tokens | `jwt_auth_token_before_sign` filter |
| Refresh tokens (opaque, 14 day, hashed at rest) | `jwt_auth_token_before_dispatch` filter + own table |
| Refresh **with rotation** + reuse detection | `POST /wp-json/jwt-auth/v1/token/refresh` |
| Logout / revocation (single + all sessions) | `POST /wp-json/jwt-auth/v1/token/revoke` |
| Active session listing | `GET /wp-json/jwt-auth/v1/sessions` |
| Revoked-token enforcement + `typ` check | `rest_pre_dispatch` guard |
| Rate limiting on `token` + `token/refresh` | `rest_pre_dispatch`, per-IP transient |

## Requirements

- WordPress 6.5+ (uses the `Requires Plugins` header)
- PHP 7.4+
- The base plugin active, with `JWT_AUTH_SECRET_KEY` defined in `wp-config.php`

## How it works

This plugin **never edits the base plugin**. It attaches to hooks the base plugin already exposes, plus registers its own REST routes and one DB table.

```
Login  ──> base /token  ──[jwt_auth_expire]──────────> 15-min access token
                        ──[jwt_auth_token_before_sign]─> + jti + typ claims
                        ──[jwt_auth_token_before_dispatch]─> + refresh_token in response

Request ─> rest_pre_dispatch (pri 4) Ext_Rate_Limit ─> 429 if over limit
        ─> rest_pre_dispatch (pri 5) Ext_Guard ──────> 401 if revoked / wrong typ
        ─> base determine_current_user (pri 10) ─────> authenticated
```

Access-token revocation is checked against a transient set (auto-expiring, no DB hit on the happy path). Refresh tokens live in a dedicated table, stored only as SHA-256 hashes.

## Install

```bash
composer install
```

This pulls the base plugin from wpackagist into `vendor/wp-plugins/`. Then make both plugins visible to WordPress and activate:

**Classic WordPress** — symlink/copy both into `wp-content/plugins/`:
```bash
ln -s "$(pwd)" wp-content/plugins/jwt-auth-pro-ext
ln -s "$(pwd)/vendor/wp-plugins/jwt-authentication-for-wp-rest-api" \
      wp-content/plugins/jwt-authentication-for-wp-rest-api
wp plugin activate jwt-authentication-for-wp-rest-api jwt-auth-pro-ext
```

**Bedrock-style** — point `installer-paths` (already set in `composer.json`) at your `web/app/plugins` dir; both land there on `composer install`.

Add the secret to `wp-config.php`:
```php
define( 'JWT_AUTH_SECRET_KEY', 'a-long-random-string' );
```

On activation this plugin creates the table `{prefix}jwt_auth_ext_refresh_tokens`. WordPress refuses to activate it unless the base plugin is active (`Requires Plugins` header).

## API

### Login (base endpoint, now enriched)
`POST /wp-json/jwt-auth/v1/token`  body: `username`, `password`
```json
{
  "token": "…",
  "user_email": "user@example.com",
  "refresh_token": "…",
  "expires_in": 900,
  "refresh_expires_in": 1209600,
  "token_type": "Bearer"
}
```

### Authenticated request
```
Authorization: Bearer <access token>
```
Rejected with `401` if the token is revoked (`jwt_auth_ext_revoked_token`) or not an access token (`jwt_auth_ext_wrong_token_type`).

### Refresh (rotation)
`POST /wp-json/jwt-auth/v1/token/refresh`  body: `refresh_token=…`
Returns a new access + refresh pair. The old refresh token is revoked. **Replaying a rotated (already-used) refresh token revokes every session for that user** — treated as a compromise.

### Logout / revoke
`POST /wp-json/jwt-auth/v1/token/revoke`  (Authorization: Bearer <access token>)
- Always: blacklists the **current access token** immediately, until its natural expiry.
- `refresh_token=…` in body → also revokes that refresh token.
- `all=true` → revokes every session for the user.

> **Note:** the access-token `jti` and refresh-token `jti` are not linked. A plain logout call (access token only, no `refresh_token`, no `all`) kills the access token but leaves the refresh token usable. For a full single-device logout, send the device's `refresh_token` in the body. For "log out everywhere", send `all=true`.

### Sessions
`GET /wp-json/jwt-auth/v1/sessions` (authenticated) → active refresh sessions:
```json
{ "sessions": [
  { "jti": "…", "created_at": "…", "last_used_at": "…", "user_agent": "…", "ip": "…", "expires_at": "…" }
] }
```

## End-to-end example

```bash
BASE=https://example.com/wp-json/jwt-auth/v1

# 1. login
RESP=$(curl -s -X POST "$BASE/token" -d "username=admin&password=secret")
ACCESS=$(echo "$RESP"  | jq -r .token)
REFRESH=$(echo "$RESP" | jq -r .refresh_token)

# 2. use the access token
curl -s "https://example.com/wp-json/wp/v2/users/me" -H "Authorization: Bearer $ACCESS"

# 3. refresh (rotates the refresh token)
RESP=$(curl -s -X POST "$BASE/token/refresh" -d "refresh_token=$REFRESH")
ACCESS=$(echo "$RESP"  | jq -r .token)
REFRESH=$(echo "$RESP" | jq -r .refresh_token)

# 4. logout this device
curl -s -X POST "$BASE/token/revoke" -H "Authorization: Bearer $ACCESS" -d "refresh_token=$REFRESH"
```

## Configuration

| Filter / option | Default | Purpose |
|-----------------|---------|---------|
| option `jwt_auth_ext_access_ttl` / filter `jwt_auth_ext_access_ttl` | 900 | Access token TTL (s) |
| filter `jwt_auth_ext_refresh_ttl` | 1209600 | Refresh token TTL (s) |
| filter `jwt_auth_ext_rate_limit_max` | 5 | Attempts per window |
| filter `jwt_auth_ext_rate_limit_window` | 300 | Window (s) |
| filter `jwt_auth_rate_limit_headers_enabled` | true | Emit `X-RateLimit-*` (base plugin's filter) |
| filter `jwt_auth_ext_refresh_before_dispatch` | — | Modify the `/token/refresh` response payload |

Example — keep access tokens at 5 minutes:
```php
add_filter( 'jwt_auth_ext_access_ttl', fn() => 300 );
```

## Data & cleanup

- Table `{prefix}jwt_auth_ext_refresh_tokens`: `id, user_id, jti, token_hash, expires_at, revoked, created_at, last_used_at, user_agent, ip`.
- Access-token blacklist: transients `jwt_auth_ext_revoked_{jti}`, TTL = remaining access-token life (self-expiring).
- A daily cron event (`jwt_auth_ext_purge_expired`) deletes expired refresh-token rows.
- Schema migrations run via the `jwt_auth_ext_db_version` option on `admin_init`.

## Tests

```bash
composer install
bash bin/install-wp-tests.sh wordpress_test root '' localhost latest   # standard WP test scaffold
JWT_AUTH_BASE_PLUGIN=/abs/path/to/jwt-auth.php vendor/bin/phpunit
```

Tests requiring the base plugin self-skip if it isn't loaded; pure repository/claims tests always run. The bootstrap auto-locates the base plugin from `WP_PLUGIN_DIR`, the composer `vendor/wp-plugins` path, or the `JWT_AUTH_BASE_PLUGIN` env var.

## Security notes

- Refresh tokens are opaque (`random_bytes(32)`); only their SHA-256 hash is stored, lookup is by hash.
- Rotation + reuse detection mitigates stolen refresh tokens (a replayed token nukes all sessions).
- Access revocation is transient-backed → per-request validation stays O(1) with no DB hit unless a token was actually revoked.
- Reuses the base plugin's `JWT_AUTH_SECRET_KEY` and signing algorithm, so issued tokens stay fully compatible with the base plugin's own validation.
- Raw tokens are never logged.

## Trade-offs

- ✅ Base plugin updates independently; no fork to maintain; clean upgrade path to the commercial PRO later.
- ⚠️ Couples to the base plugin's filter names and its bundled `Tmeister\Firebase\JWT` library. The base version is pinned via composer (`^1.3`) and integration tests cover the contract.

## License

GPL-2.0-or-later.
