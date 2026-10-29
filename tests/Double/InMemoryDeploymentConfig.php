<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\DatabaseSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueChange;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueSource;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigUnreadable;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigWriter;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\StaleDeploymentConfig;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;

/**
 * The deployment and committed configuration of a store, in memory: a key ring, encrypted `system`
 * values of both files, the file owner, whether the file holds only literal data, whether it can be
 * written, and the strings its names mark as secret.
 *
 * Writes follow the port's contract exactly: the ring fingerprint and every expected old value are
 * checked first, and a mismatch writes nothing. Every applied write is recorded. A crash hook runs right
 * after an applied write and may throw, so a test can stop a use case between a ring write and the save
 * that would record it. A test plays another writer with {@see replaceRing()} and {@see putSystemValue()}, and a deploy
 * of the committed configuration with {@see deployCommittedSystemValues()}.
 */
final class InMemoryDeploymentConfig implements DeploymentConfigReader, DeploymentConfigWriter
{
    /**
     * @var array<string, SystemValue> path joined by `/` => value of the deployment configuration
     */
    private array $systemValues = [];

    /**
     * @var list<SystemValue>
     */
    private array $committedSystemValues;

    private readonly DatabaseSettings $databaseSettings;

    /**
     * @var list<array{ring: KeyRing, expected: string, changes: list<SystemValueChange>}>
     */
    private array $writes = [];

    private ?\Closure $afterWrite = null;

    private bool $writable = true;

    /**
     * @param list<SystemValue> $systemValues          encrypted values of the deployment configuration
     * @param list<SystemValue> $committedSystemValues encrypted values of the committed configuration
     * @param list<string>      $secretStrings         the strings the file's names mark as secret
     */
    public function __construct(
        private KeyRing $ring,
        array $systemValues = [],
        array $committedSystemValues = [],
        private readonly int $ownerUid = 1000,
        private bool $literal = true,
        ?DatabaseSettings $databaseSettings = null,
        private readonly ?CallLog $log = null,
        private readonly array $secretStrings = [],
    ) {
        foreach ($systemValues as $value) {
            $this->putSystemValue($value);
        }
        $this->committedSystemValues = $committedSystemValues;
        $this->databaseSettings = $databaseSettings
            ?? new DatabaseSettings('127.0.0.1', 3306, null, 'store', 'store', 'not-a-real-password', '', '');
    }

    public function keyRing(): KeyRing
    {
        return $this->ring;
    }

    public function databaseSettings(): DatabaseSettings
    {
        return $this->databaseSettings;
    }

    public function systemValues(): array
    {
        return array_values($this->systemValues);
    }

    public function committedSystemValues(): array
    {
        return $this->committedSystemValues;
    }

    public function ownerUid(): int
    {
        return $this->ownerUid;
    }

    public function holdsOnlyLiteralData(): bool
    {
        return $this->literal;
    }

    public function isWritable(): bool
    {
        return $this->writable;
    }

    public function secretStrings(): array
    {
        return $this->secretStrings;
    }

    public function write(KeyRing $ring, string $expectedRingFingerprint, array $changes): void
    {
        $current = $this->ring->fingerprint();
        if ($current !== $expectedRingFingerprint) {
            throw new StaleDeploymentConfig(sprintf(
                'The deployment configuration holds the key ring %s, not the expected %s; nothing was written.',
                $current,
                $expectedRingFingerprint,
            ));
        }
        foreach ($changes as $change) {
            $value = $this->systemValues[$change->pathString()] ?? null;
            if ($value === null || !$value->ciphertext()->equals($change->expectedOld())) {
                throw new StaleDeploymentConfig(sprintf(
                    'The system value at %s is not the expected one; nothing was written.',
                    $change->pathString(),
                ));
            }
        }

        $this->ring = $ring;
        foreach ($changes as $change) {
            $this->systemValues[$change->pathString()] = new SystemValue($change->path(), $change->new(), SystemValueSource::Env);
        }
        $this->writes[] = ['ring' => $ring, 'expected' => $expectedRingFingerprint, 'changes' => $changes];
        $this->log?->record('config.write ' . $ring->fingerprint());

        if ($this->afterWrite !== null) {
            ($this->afterWrite)($ring, $changes);
        }
    }

    /**
     * Runs after every applied write, with the written ring and changes; it may throw to play a crash
     * that happens after the file was replaced. Null removes the hook.
     *
     * @param (\Closure(KeyRing, list<SystemValueChange>): void)|null $hook
     */
    public function afterWrite(?\Closure $hook): void
    {
        $this->afterWrite = $hook;
    }

    /**
     * Plays another writer replacing the key ring (the admin, a deploy, a stale copy written back).
     */
    public function replaceRing(KeyRing $ring): void
    {
        $this->ring = $ring;
    }

    /**
     * Plays another writer setting a system value of the deployment configuration.
     *
     * @throws DeploymentConfigUnreadable when the value is not from the deployment configuration
     */
    public function putSystemValue(SystemValue $value): void
    {
        if ($value->source() !== SystemValueSource::Env) {
            throw new DeploymentConfigUnreadable('Only values of the deployment configuration can be put into it.');
        }
        $this->systemValues[$value->pathString()] = $value;
    }

    /**
     * Plays a deploy that ships a new committed configuration: its encrypted values become these.
     *
     * @param list<SystemValue> $values encrypted values of the committed configuration
     *
     * @throws DeploymentConfigUnreadable when a value is not from the committed configuration
     */
    public function deployCommittedSystemValues(array $values): void
    {
        foreach ($values as $value) {
            if ($value->source() !== SystemValueSource::Committed) {
                throw new DeploymentConfigUnreadable('Only values of the committed configuration can be deployed into it.');
            }
        }
        $this->committedSystemValues = $values;
    }

    /**
     * Plays a file, or a directory holding it, that this process cannot write.
     */
    public function makeUnwritable(): void
    {
        $this->writable = false;
    }

    /**
     * Plays a file that came to hold more than literal data.
     */
    public function holdNonLiteralData(): void
    {
        $this->literal = false;
    }

    /**
     * @return list<array{ring: KeyRing, expected: string, changes: list<SystemValueChange>}> the applied writes, oldest first
     */
    public function writes(): array
    {
        return $this->writes;
    }
}
