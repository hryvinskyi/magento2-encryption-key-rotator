<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Support;

use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Cipher;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\CiphertextParser;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\PlaintextFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyGenerator;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRingFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRingParser;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeySlotFactory;
use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\ContainerFactory;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * The key and crypto services exactly as the tool's real container builds them, generated factories
 * included, for tests that must exercise the shipped wiring rather than test doubles.
 *
 * The container is compiled once per process, into a scratch directory removed when the process ends:
 * a generated factory class, once loaded, cannot be loaded again from a second build directory.
 */
final class CryptoServices
{
    private static ?self $shared = null;

    private function __construct(
        private readonly ContainerInterface $container,
    ) {}

    /**
     * The services of the real service configuration, compiled on first use.
     */
    public static function shared(): self
    {
        if (self::$shared !== null) {
            return self::$shared;
        }

        $buildDirectory = TemporaryDirectory::create('key-rotator-crypto-services');
        register_shutdown_function(static function () use ($buildDirectory): void {
            TemporaryDirectory::remove($buildDirectory);
        });
        $root = dirname(__DIR__, 2);
        $container = (new ContainerFactory(
            $root . '/tests/Fixtures/Container/crypto-services.php',
            ['Hryvinskyi\\EncryptionKeyRotator\\' => $root . '/src'],
        ))->compile($buildDirectory);

        return self::$shared = new self($container);
    }

    public function keys(): KeyFactory
    {
        return $this->service(KeyFactory::class);
    }

    public function slots(): KeySlotFactory
    {
        return $this->service(KeySlotFactory::class);
    }

    public function rings(): KeyRingFactory
    {
        return $this->service(KeyRingFactory::class);
    }

    public function ringParser(): KeyRingParser
    {
        return $this->service(KeyRingParser::class);
    }

    public function keyGenerator(): KeyGenerator
    {
        return $this->service(KeyGenerator::class);
    }

    public function ciphertextParser(): CiphertextParser
    {
        return $this->service(CiphertextParser::class);
    }

    public function plaintexts(): PlaintextFactory
    {
        return $this->service(PlaintextFactory::class);
    }

    public function cipher(): Cipher
    {
        return $this->service(Cipher::class);
    }

    /**
     * @template T of object
     *
     * @param class-string<T> $id
     *
     * @return T
     */
    private function service(string $id): object
    {
        $service = $this->container->get('test.' . $id);
        if (!$service instanceof $id) {
            throw new \LogicException(sprintf('The container holds no %s.', $id));
        }

        return $service;
    }
}
