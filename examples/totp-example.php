<?php
/**
 * TOTP demo — enrollment + verification, no dependencies.
 *
 * php examples/totp-example.php
 */

require __DIR__ . '/../src/Totp.php';

// --- 1. Enrollment: generate a secret and show the provisioning URI ---
$secret = Totp::generateSecret(); // 20 random bytes, base32-encoded
$account = 'user@example.com';
$issuer  = 'MyApp';

$uri = Totp::getProvisioningUri($secret, $account, $issuer);

echo "Secret:  $secret\n";
echo "URI:     $uri\n\n";

// Turn it into a QR code the user can scan (any QR API works):
echo "QR: https://api.qrserver.com/v1/create-qr-code/?size=200x200&data="
   . rawurlencode($uri) . "\n\n";

// --- 2. The user scans it; their app now shows the same code we compute ---
$code = Totp::getCode($secret);
echo "Current code (what the authenticator app shows): $code\n";

// Codes rotate every 30 s — same window, same code:
echo 'Same window again: ' . Totp::getCode($secret) . "\n\n";

// --- 3. Verification ---
$ok = Totp::verify($secret, $code);
echo 'Verify correct code: ' . var_export($ok, true) . "\n";

$wrong = Totp::verify($secret, '000000');
echo 'Verify wrong code:   ' . var_export($wrong, true) . "\n";

// --- 4. Base32 round-trip sanity check ---
$raw = random_bytes(20);
echo 'Base32 round-trip ok: '
   . var_export(Totp::base32Decode(Totp::base32Encode($raw)) === $raw, true) . "\n";
