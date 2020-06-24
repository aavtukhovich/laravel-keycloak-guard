<?php

namespace KeycloakGuard;

use Firebase\JWT\JWT;

class Token
{
    /**
     * Decode a JWT token
     *
     * @param  string  $token
     * @param  string  $publicKey
     * @return mixed|null
     */
    public static function decode(string $token = null, string $publicKey)
    {
        list($headb64, $bodyb64, $cryptob64) = explode('.', $token);
        $payload = json_decode(static::urlsafeB64Decode($bodyb64), false, 512, JSON_BIGINT_AS_STRING);
        return $payload;
    }

    /**
     * Decode a string with URL-safe Base64.
     *
     * @param string $input A Base64 encoded string
     *
     * @return string A decoded string
     */
    public static function urlsafeB64Decode($input)
    {
        $remainder = \strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= \str_repeat('=', $padlen);
        }
        return \base64_decode(\strtr($input, '-_', '+/'));
    }
}
