<?php

declare(strict_types=1);

/*
 * Reads column definitions with the store's own schema reader, taken from the installed code base
 * MAGENTO_ROOT names: the DefinitionAggregator that `setup:upgrade` and `setup:db:status` run every
 * column of the database through, built by the store's object manager from its own configuration.
 * Its var and generated directories point at a scratch directory that is removed afterwards. The log
 * handlers still write below the code base's own var/log, as every bin/magento run does.
 *
 * Input, JSON on stdin:
 *   {"columns": [{"name": ..., "type": <DATA_TYPE>, "definition": <COLUMN_TYPE>, "nullable": bool, ...}, ...]}
 *   (one entry per column, in the shape the store's DbSchemaReader takes from information_schema.COLUMNS)
 * Output, JSON on stdout: {"results": [{"read": "<type the store read>"} | {"refused": "<message>"}, ...]}.
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
function invoke(object $object, string $method, array $arguments): mixed
{
    $callable = [$object, $method];
    if (!is_callable($callable)) {
        stop(sprintf('%s has no method %s().', $object::class, $method), 4);
    }

    return $callable(...$arguments);
}

function objectOf(mixed $value, string $what): object
{
    if (!is_object($value)) {
        stop(sprintf('%s is not an object.', $what), 5);
    }

    return $value;
}

function removeTree(string $path): void
{
    if (!is_dir($path) || is_link($path)) {
        @unlink($path);

        return;
    }
    foreach (scandir($path) ?: [] as $entry) {
        if ($entry !== '.' && $entry !== '..') {
            removeTree($path . '/' . $entry);
        }
    }
    @rmdir($path);
}

$root = getenv('MAGENTO_ROOT');
if (!is_string($root) || $root === '') {
    stop('MAGENTO_ROOT is not set.', 2);
}
try {
    // The store's own autoloader, registered where its bootstrap looks for it.
    require $root . '/app/autoload.php';
} catch (Throwable $failure) {
    stop(sprintf('Cannot load the code base of %s: %s', $root, $failure->getMessage()), 3);
}

$input = json_decode((string) stream_get_contents(STDIN), true);
if (!is_array($input) || !is_array($input['columns'] ?? null)) {
    stop('Expected {"columns": list} on stdin.', 2);
}

$create = ['Magento\\Framework\\App\\Bootstrap', 'create'];
if (!is_callable($create)) {
    stop('Magento\\Framework\\App\\Bootstrap::create() is not available in this code base.', 4);
}

$scratch = sys_get_temp_dir() . '/magento-schema-reader-' . bin2hex(random_bytes(8));
if (!mkdir($scratch, 0700)) {
    stop('Cannot create a scratch directory.', 2);
}

try {
    $directories = [];
    foreach (['var' => 'var', 'cache' => 'var/cache', 'log' => 'var/log', 'session' => 'var/session', 'tmp' => 'var/tmp', 'generated' => 'generated', 'code' => 'generated/code', 'metadata' => 'generated/metadata'] as $code => $path) {
        $directories[$code] = ['path' => $scratch . '/' . $path];
    }
    // MAGE_DIRS is the bootstrap parameter that relocates the directory list.
    $objectManager = objectOf(invoke(objectOf($create($root, ['MAGE_DIRS' => $directories]), 'Bootstrap::create()'), 'getObjectManager', []), 'The object manager');
    $aggregator = objectOf(invoke($objectManager, 'get', ['Magento\\Framework\\Setup\\Declaration\\Schema\\Db\\DefinitionAggregator']), 'The DefinitionAggregator');

    $results = [];
    foreach ($input['columns'] as $column) {
        if (!is_array($column) || !is_string($column['type'] ?? null)) {
            stop('Every column needs a "type".', 2);
        }
        try {
            $read = invoke($aggregator, 'fromDefinition', [$column]);
            $results[] = ['read' => is_array($read) && is_string($read['type'] ?? null) ? $read['type'] : ''];
        } catch (InvalidArgumentException $refused) {
            $results[] = ['refused' => $refused->getMessage()];
        }
    }
} finally {
    removeTree($scratch);
}

fwrite(STDOUT, (string) json_encode(['results' => $results], JSON_THROW_ON_ERROR));
