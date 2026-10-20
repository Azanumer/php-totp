<?php
/**
 * Totp
 *
 * Dependency-free RFC 6238 TOTP (time-based one-time passwords).
 *
 * - PHP 7.4+ compatible, zero dependencies
 * - HMAC-SHA1, 30-second period, 6 digits (RFC 6238 / RFC 4226 defaults)
 * - Base32 encode/decode implemented internally (uppercase RFC 4648
 *   alphabet, padding stripped — the format authenticator apps expect)
 * - Constant-time code comparison via hash_equals()
 *
 * All methods are static: Totp::generateSecret(), Totp::getCode(), ...
 */

class Totp
{
    /** RFC 4648 base32 alphabet (uppercase). */
    const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * Generate a new random secret, base32-encoded and ready to store.
     *
     * @param int $bytes Raw entropy bytes (20 = the RFC 4226 recommendation).
     */
    public static function generateSecret($bytes = 20)
    {
        if ($bytes < 10) {
            throw new InvalidArgumentException('Secret needs at least 10 bytes of entropy.');
        }
        return self::base32Encode(random_bytes($bytes));
    }

    /**
     * Base32-encode raw bytes (RFC 4648, uppercase, no padding).
     */
    public static function base32Encode($data)
    {
        $bits = '';
        $len = strlen($data);
        for ($i = 0; $i < $len; $i++) {
            $bits .= str_pad(decbin(ord($data[$i])), 8, '0', STR_PAD_LEFT);
        }
        $out = '';
        $bitLen = strlen($bits);
        for ($i = 0; $i < $bitLen; $i += 5) {
            $chunk = str_pad(substr($bits, $i, 5), 5, '0', STR_PAD_RIGHT);
            $out .= self::ALPHABET[bindec($chunk)];
        }
        return $out;
    }

    /**
     * Base32-decode a secret back to raw bytes.
     * Accepts upper/lowercase, with or without "=" padding.
     */
    public static function base32Decode($encoded)
    {
        $encoded = strtoupper(rtrim($encoded, '='));
        if ($encoded === '') {
            throw new InvalidArgumentException('Empty base32 secret.');
        }
        $bits = '';
        $len = strlen($encoded);
        for ($i = 0; $i < $len; $i++) {
            $pos = strpos(self::ALPHABET, $encoded[$i]);
            if ($pos === false) {
                throw new InvalidArgumentException('Invalid base32 character: ' . $encoded[$i]);
            }
            $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }
        $out = '';
        $bitLen = strlen($bits);
        for ($i = 0; $i + 8 <= $bitLen; $i += 8) {
            $out .= chr(bindec(substr($bits, $i, 8)));
        }
        return $out;
    }

    /**
     * Compute the TOTP code for a secret at a given time.
     *
     * @param string   $secret Base32 secret (as produced by generateSecret()).
     * @param int|null $time   Unix timestamp; defaults to now.
     * @param int      $period Time-step in seconds (default 30).
     * @param int      $digits Code length (default 6).
     * @return string Zero-padded numeric code.
     */
    public static function getCode($secret, $time = null, $period = 30, $digits = 6)
    {
        if ($time === null) {
            $time = time();
        }
        $counter = (int) floor($time / $period);

        // 8-byte big-endian counter (timestamps fit 32 bits for millennia).
        $counterBytes = pack('N2', 0, $counter);

        $hash = hash_hmac('sha1', $counterBytes, self::base32Decode($secret), true);

        // Dynamic truncation (RFC 4226 §5.4).
        $offset = ord($hash[19]) & 0x0f;
        $binary = ((ord($hash[$offset]) & 0x7f) << 24)
                 | (ord($hash[$offset + 1]) << 16)
                 | (ord($hash[$offset + 2]) << 8)
                 |  ord($hash[$offset + 3]);

        $otp = $binary % pow(10, $digits);
        return str_pad((string) $otp, $digits, '0', STR_PAD_LEFT);
    }

    /**
     * Verify a user-submitted code. Allows $discrepancy time-steps of clock
     * skew on either side. Uses hash_equals() for constant-time comparison.
     *
     * @param string $secret
     * @param string $code   The code the user typed.
     * @param int    $discrepancy Allowed steps of drift (default 1).
     */
    public static function verify($secret, $code, $discrepancy = 1, $period = 30, $digits = 6)
    {
        $code = (string) $code;
        if (!preg_match('/^\d{' . $digits . '}$/', $code)) {
            return false;
        }
        $time = time();
        for ($i = -$discrepancy; $i <= $discrepancy; $i++) {
            $expected = self::getCode($secret, $time + ($i * $period), $period, $digits);
            if (hash_equals($expected, $code)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Build the otpauth:// provisioning URI for QR-code enrollment
     * (Google Authenticator, Authy, 1Password, …).
     *
     * @param string      $secret  Base32 secret.
     * @param string      $account User identifier shown in the app (email).
     * @param string|null $issuer  Your service name (optional).
     */
    public static function getProvisioningUri($secret, $account, $issuer = null, $period = 30, $digits = 6)
    {
        $label = ($issuer !== null && $issuer !== '')
            ? rawurlencode($issuer) . ':' . rawurlencode($account)
            : rawurlencode($account);

        $params = array(
            'secret'    => $secret,
            'issuer'    => $issuer,
            'algorithm' => 'SHA1',
            'digits'    => $digits,
            'period'    => $period,
        );
        $query = http_build_query(
            array_filter($params, function ($v) { return $v !== null && $v !== ''; }),
            '',
            '&',
            PHP_QUERY_RFC3986
        );

        return 'otpauth://totp/' . $label . '?' . $query;
    }
}
