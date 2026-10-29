<?php

declare(strict_types=1);

/*
 * Runs operations on the store's own Encryptor, taken from the installed code base MAGENTO_ROOT names,
 * without booting the application: the Encryptor is built by hand on a deployment configuration whose
 * override data carries `crypt/key`, and whose reader points at an empty directory, so no
 * configuration file of the code base is read.
 *
 * Input, JSON on stdin:
 *   {"ring": "<crypt/key value>", "operations": [{"op": "<name>", ...}, ...]}
 * Operations:
 *   encrypt      {"plaintext": "<base64 of the bytes>"}  -> {"ciphertext": "<stored value>"}
 *   decrypt      {"value": "<stored value>"}             -> {"plaintext": "<base64 of the bytes>"}
 *   keyVersion   {}                                      -> {"keyVersion": <index the Encryptor encrypts under>}
 *   exportKeys   {}                                      -> {"keys": "<the ring as the Encryptor exports it>"}
 * Output, JSON on stdout: {"results": [<one result per operation, in order>]}.
 *
 * The store's classes are named as strings: this package does not depend on them, they come from the
 * autoloader of MAGENTO_ROOT at run time.
 */

ini_set('display_errors', 'stderr');

/**
 * @return never
 */
function stop(string $message, int $exitCode): void
{
    fwrite(STDERR, $message . "\n");
    exit($exitCode);
}

/**
 * @param list<mixed> $arguments
 */
function construct(string $class, array $arguments): object
{
    if (!class_exists($class)) {
        stop(sprintf('Class %s is not available in this code base.', $class), 4);
    }

    return new $class(...$arguments);
}

/**
 * @param list<mixed> $arguments
 */
function invoke(object $object, string $method, array $arguments): mixed
{
    $callable = [$object, $method];
    if (!is_callable($callable)) {
        stop(sprintf('%s has no method %s().', $object::class, $method), 4);
    }

    return $callable(...$arguments);
}

function stringOf(mixed $value, string $what): string
{
    if (!is_string($value)) {
        stop(sprintf('%s is not a string.', $what), 5);
    }

    return $value;
}

$root = getenv('MAGENTO_ROOT');
if (!is_string($root) || $root === '') {
    stop('MAGENTO_ROOT is not set.', 2);
}
try {
    require $root . '/vendor/autoload.php';
} catch (Throwable $failure) {
    stop(sprintf('Cannot load the code base of %s: %s', $root, $failure->getMessage()), 3);
}

$input = json_decode((string) stream_get_contents(STDIN), true);
if (!is_array($input) || !is_string($input['ring'] ?? null) || !is_array($input['operations'] ?? null)) {
    stop('Expected {"ring": string, "operations": list} on stdin.', 2);
}

$emptyRoot = sys_get_temp_dir() . '/magento-encryptor-' . bin2hex(random_bytes(8));
if (!mkdir($emptyRoot, 0700)) {
    stop('Cannot create an empty root directory.', 2);
}

try {
    $reader = construct('Magento\\Framework\\App\\DeploymentConfig\\Reader', [
        construct('Magento\\Framework\\App\\Filesystem\\DirectoryList', [$emptyRoot]),
        construct('Magento\\Framework\\Filesystem\\DriverPool', []),
        construct('Magento\\Framework\\Config\\File\\ConfigFilePool', []),
    ]);
    $deploymentConfig = construct('Magento\\Framework\\App\\DeploymentConfig', [
        $reader,
        ['crypt' => ['key' => $input['ring']]],
    ]);
    $encryptor = construct('Magento\\Framework\\Encryption\\Encryptor', [
        construct('Magento\\Framework\\Math\\Random', []),
        $deploymentConfig,
        construct('Magento\\Framework\\Encryption\\KeyValidator', []),
    ]);

    $operations = [
        'encrypt' => static function (array $operation) use ($encryptor): array {
            $bytes = base64_decode(stringOf($operation['plaintext'] ?? null, 'encrypt.plaintext'), true);
            if ($bytes === false) {
                stop('encrypt.plaintext is not base64.', 5);
            }

            return ['ciphertext' => stringOf(invoke($encryptor, 'encrypt', [$bytes]), 'Encryptor::encrypt()')];
        },
        'decrypt' => static function (array $operation) use ($encryptor): array {
            $value = stringOf($operation['value'] ?? null, 'decrypt.value');

            return ['plaintext' => base64_encode(stringOf(invoke($encryptor, 'decrypt', [$value]), 'Encryptor::decrypt()'))];
        },
        'keyVersion' => static function () use ($encryptor): array {
            $keyVersion = (new ReflectionProperty($encryptor, 'keyVersion'))->getValue($encryptor);
            if (!is_int($keyVersion)) {
                stop('Encryptor::$keyVersion is not an integer.', 5);
            }

            return ['keyVersion' => $keyVersion];
        },
        'exportKeys' => static fn(): array => ['keys' => stringOf(invoke($encryptor, 'exportKeys', []), 'Encryptor::exportKeys()')],
    ];

    $results = [];
    foreach ($input['operations'] as $operation) {
        if (!is_array($operation) || !is_string($operation['op'] ?? null) || !isset($operations[$operation['op']])) {
            stop('Every operation needs a known "op".', 2);
        }
        $results[] = $operations[$operation['op']]($operation);
    }
} finally {
    rmdir($emptyRoot);
}

fwrite(STDOUT, json_encode(['results' => $results], JSON_THROW_ON_ERROR));
