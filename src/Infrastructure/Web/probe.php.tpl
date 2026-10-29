<?php

/*
 * A one-time probe of the encryption key rotation tool. It answers only the request that carries its
 * token, and only with an HMAC of the key ring the PHP running it sees, keyed by that token: nothing
 * else about the configuration leaves it. The tool deletes this file right after the request.
 */

declare(strict_types=1);

ini_set('display_errors', '0');
header('Cache-Control: no-store');

$token = {{token}};
$given = $_GET['t'] ?? null;
if (!is_string($given) || !hash_equals($token, $given)) {
    http_response_code(404);

    return;
}

$config = include {{deploymentConfig}};
$cryptKey = is_array($config) && is_array($config['crypt'] ?? null) && is_string($config['crypt']['key'] ?? null)
    ? $config['crypt']['key']
    : '';
$entries = preg_split('/\s+/', trim($cryptKey));

header('Content-Type: text/plain');
echo hash_hmac('sha256', implode("\n", $entries === false ? [] : $entries), $token);
