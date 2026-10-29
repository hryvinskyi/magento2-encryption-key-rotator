<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Double;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\StaleDeploymentConfig;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRingParser;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRun;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\CallLog;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeyRingFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeySlotFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\InMemoryDeploymentConfig;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\InMemoryRunStore;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use PHPUnit\Framework\TestCase;

/**
 * A crash hook throws after the write it follows has landed, so a use case test can stop a step on
 * either side of a key ring write.
 */
final class CrashHooksTest extends TestCase
{
    public function testACrashAfterTheDeploymentConfigWriteLeavesTheWriteInPlace(): void
    {
        $before = $this->ring(KeyMaterial::rawKey());
        $after = $this->ring($before->export() . "\n" . KeyMaterial::base64Key());
        $log = new CallLog();
        $config = new InMemoryDeploymentConfig($before, log: $log);
        $config->afterWrite(static function (): never {
            throw new \RuntimeException('crash');
        });

        try {
            $config->write($after, $before->fingerprint(), []);
            self::fail('The crash hook did not run.');
        } catch (\RuntimeException) {
            $this->addToAssertionCount(1);
        }

        self::assertSame($after->fingerprint(), $config->keyRing()->fingerprint());
        self::assertCount(1, $config->writes());
        self::assertSame(['config.write ' . $after->fingerprint()], $log->events());
    }

    public function testAStaleWriteNeverReachesTheCrashHook(): void
    {
        $before = $this->ring(KeyMaterial::rawKey());
        $config = new InMemoryDeploymentConfig($before);
        $config->afterWrite(static function (): never {
            throw new \LogicException('The hook ran for a write that did not happen.');
        });

        $this->expectException(StaleDeploymentConfig::class);

        $config->write($before, $this->ring(KeyMaterial::rawKey())->fingerprint(), []);
    }

    public function testACrashAfterARunSaveLeavesTheSaveInPlace(): void
    {
        $store = new InMemoryRunStore();
        $run = new RotationRun(new RunId(str_repeat('1', 32)), '00000000000000aa', [0], 1, new \DateTimeImmutable('2026-10-29T10:00:00.000000+00:00'));
        $run->keyPending(2, '00000000000000bb', new \DateTimeImmutable('2026-10-29T10:00:01.000000+00:00'));
        $store->afterSave(static function (RotationRun $saved): never {
            throw new \RuntimeException('crash after saving ' . $saved->state()->value);
        });

        try {
            $store->save($run);
            self::fail('The crash hook did not run.');
        } catch (\RuntimeException $crash) {
            self::assertSame('crash after saving key_pending', $crash->getMessage());
        }
        $store->afterSave(null);

        self::assertSame(RunState::KeyPending, $store->get($run->id())->state());
    }

    private function ring(string $cryptKey): KeyRing
    {
        return (new KeyRingParser(new DirectKeySlotFactory(), new DirectKeyRingFactory()))->parse($cryptKey);
    }
}
