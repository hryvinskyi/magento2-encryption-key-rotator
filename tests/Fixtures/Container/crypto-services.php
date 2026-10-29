<?php

declare(strict_types=1);

use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Cipher;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\CiphertextParser;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\PlaintextFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyGenerator;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRingFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRingParser;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeySlotFactory;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

/*
 * The tool's real service configuration, with its key and crypto services reachable from a test: each
 * gets a public alias `test.<interface or class>`, so a test exercises exactly the objects and the
 * generated factories the shipped container builds.
 */
return static function (ContainerConfigurator $container): void {
    $container->import(dirname(__DIR__, 3) . '/config/services.php');

    $services = $container->services();
    foreach ([
        KeyFactory::class,
        KeySlotFactory::class,
        KeyRingFactory::class,
        KeyRingParser::class,
        KeyGenerator::class,
        CiphertextParser::class,
        PlaintextFactory::class,
        Cipher::class,
    ] as $id) {
        $services->alias('test.' . $id, $id)->public();
    }
};
