<?php

declare(strict_types=1);

/*
 * Prints whether the deployment configuration of the Magento root given as the first argument can be
 * replaced, as the real container's reader sees it in this process: `true` or `false`. A test runs it as
 * an unprivileged user when the tests run as root, for whom every file is writable whatever its mode.
 */

use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\DeploymentConfigServices;

require dirname(__DIR__, 4) . '/vendor/autoload.php';

$root = $argv[1] ?? '';
if ($root === '') {
    fwrite(STDERR, "Give the Magento root.\n");
    exit(2);
}

$services = DeploymentConfigServices::shared();
$services->pointAtRoot($root);
echo $services->get(DeploymentConfigReader::class)->isWritable() ? 'true' : 'false';
