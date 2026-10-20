# php-totp

Dependency-free RFC 6238 TOTP (time-based one-time passwords) for PHP 7.4+.
No Composer, no extensions beyond the standard library — one class with
static methods.

```php
// Enrollment
$secret = Totp::generateSecret();                       // store per user
$uri    = Totp::getProvisioningUri($secret, 'user@example.com', 'MyApp');
// → otpauth://totp/MyApp:user%40example.com?secret=...&issuer=MyApp&...
// render $uri as a QR code; the user scans it with any authenticator app

// Verification
if (Totp::verify($secret, $_POST['code'])) {
    // logged in — allow ±1 step (30 s) of clock skew by default
}
```

## Methods

| Method | Purpose |
|--------|---------|
| `generateSecret($bytes = 20)` | Cryptographically random base32 secret (`random_bytes`) |
| `base32Encode($data)` / `base32Decode($s)` | RFC 4648 base32, uppercase, padding stripped; decode accepts lower/upper case and `=` padding |
| `getCode($secret, $time = null, $period = 30, $digits = 6)` | The numeric code for a moment in time |
| `verify($secret, $code, $discrepancy = 1, ...)` | Constant-time (`hash_equals`) check with clock-skew tolerance |
| `getProvisioningUri($secret, $account, $issuer = null, ...)` | `otpauth://totp/…` URI for QR enrollment |

Implementation follows RFC 4226 §5.4 dynamic truncation over
`hash_hmac('sha1', $counter, $key)` with an 8-byte big-endian counter.

## Files

- `src/Totp.php` — the whole library (one class, static methods)
- `examples/totp-example.php` — enrollment + verify demo
  (`php examples/totp-example.php`)

## Requirements

PHP 7.4+. Uses only core functions (`random_bytes`, `hash_hmac`,
`hash_equals`, `pack`).

## License

MIT — see `LICENSE`.
