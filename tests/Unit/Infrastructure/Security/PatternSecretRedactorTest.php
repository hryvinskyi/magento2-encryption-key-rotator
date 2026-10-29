<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Infrastructure\Security;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\DatabaseSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigUnreadable;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Security\PatternSecretRedactor;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\InMemoryDeploymentConfig;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\ProbeStoreRoot;
use PHPUnit\Framework\TestCase;

/**
 * Ciphertexts, long base64 runs (slashes JSON-escaped or not), the database password and every string
 * the configuration names secret never leave the redactor; ordinary text does, unchanged. The secrets
 * are read only when text is first redacted.
 */
final class PatternSecretRedactorTest extends TestCase
{
    private const PASSWORD = 'S3cret-Pass!';
    private const QUEUE_PASSWORD = 'amqp/Pass-77';
    private const API_TOKEN = 'tok_live_Q9';

    public function testACiphertextIsRedactedWhole(): void
    {
        $ciphertext = '1:3:' . base64_encode(random_bytes(40));

        $redacted = $this->redactor()->redact('Cannot decrypt ' . $ciphertext . ' in core_config_data.');

        self::assertSame('Cannot decrypt [redacted] in core_config_data.', $redacted);
    }

    public function testKeyEntriesAndOtherLongBase64RunsAreRedacted(): void
    {
        $raw = KeyMaterial::rawKey();
        $encoded = KeyMaterial::base64Key();

        $redacted = $this->redactor()->redact(sprintf('keys %s and %s', $raw, $encoded));

        self::assertSame('keys [redacted] and [redacted]', $redacted);
    }

    public function testARunShorterThan32CharactersIsKept(): void
    {
        $short = str_repeat('a', 31);

        self::assertSame('value ' . $short, $this->redactor()->redact('value ' . $short));
    }

    public function testTheDatabasePasswordIsRedactedWhereverItAppears(): void
    {
        $redacted = $this->redactor()->redact(sprintf("Access denied for 'store' using password '%s' (%s)", self::PASSWORD, self::PASSWORD));

        self::assertSame("Access denied for 'store' using password '[redacted]' ([redacted])", $redacted);
    }

    public function testEveryStringTheConfigurationNamesSecretIsRedactedAsWrittenAndAsJsonWritesIt(): void
    {
        $redacted = $this->redactor()->redact(sprintf(
            'queue %s, token %s, in JSON {"password":"%s"}',
            self::QUEUE_PASSWORD,
            self::API_TOKEN,
            str_replace('/', '\\/', self::QUEUE_PASSWORD),
        ));

        self::assertSame('queue [redacted], token [redacted], in JSON {"password":"[redacted]"}', $redacted);
    }

    public function testACiphertextAndABase64RunWhoseSlashesJsonEscapedAreRedacted(): void
    {
        $payload = str_repeat('ab/', 12) . 'cd==';
        $escaped = str_replace('/', '\\/', $payload);

        $redacted = $this->redactor()->redact(sprintf('{"value":"1:3:%s","raw":"%s"}', $escaped, $escaped));

        self::assertSame('{"value":"[redacted]","raw":"[redacted]"}', $redacted);
    }

    public function testOrdinaryTextIsUnchanged(): void
    {
        $line = 'SQLSTATE[HY000] [2002] Connection refused at 12:30:45 (line 3:1)';

        self::assertSame($line, $this->redactor()->redact($line));
    }

    public function testTheSecretsAreReadOnlyWhenTextIsFirstRedactedAndThenKept(): void
    {
        $reader = $this->countingReader(new InMemoryDeploymentConfig(
            ProbeStoreRoot::ring(KeyMaterial::rawKey()),
            databaseSettings: $this->settings(),
            secretStrings: [self::API_TOKEN],
        ));
        $redactor = new PatternSecretRedactor($reader);
        self::assertCount(0, $reader);

        $redactor->redact('one');
        $redactor->redact('two ' . self::PASSWORD);
        self::assertSame('three [redacted]', $redactor->redact('three ' . self::API_TOKEN));

        self::assertCount(2, $reader, 'The password and the secret strings are each read once.');
    }

    public function testAnUnreadableConfigurationStillRedactsByPatternAndIsAskedAgainLater(): void
    {
        $reader = $this->countingReader(null);
        $redactor = new PatternSecretRedactor($reader);
        $key = KeyMaterial::rawKey();

        self::assertSame('env.php broken near [redacted]', $redactor->redact('env.php broken near ' . $key));
        $redactor->redact('again');

        self::assertCount(2, $reader);
    }

    public function testADumpOfTheRedactorHidesThePassword(): void
    {
        $redactor = $this->redactor();
        $redactor->redact('read the password');

        self::assertStringNotContainsString(self::PASSWORD, print_r($redactor, true));
    }

    private function redactor(): PatternSecretRedactor
    {
        return new PatternSecretRedactor(new InMemoryDeploymentConfig(
            ProbeStoreRoot::ring(KeyMaterial::rawKey()),
            databaseSettings: $this->settings(),
            secretStrings: [self::QUEUE_PASSWORD, self::API_TOKEN],
        ));
    }

    private function settings(): DatabaseSettings
    {
        return new DatabaseSettings('db', 3306, null, 'store', 'store', self::PASSWORD, '', '');
    }

    /**
     * A reader that counts how often the database settings and the secret strings are asked for, and
     * fails when it has no configuration to delegate to.
     */
    private function countingReader(?InMemoryDeploymentConfig $config): DeploymentConfigReader&\Countable
    {
        return new class ($config) implements DeploymentConfigReader, \Countable {
            /**
             * @var int<0, max>
             */
            private int $reads = 0;

            public function __construct(private readonly ?InMemoryDeploymentConfig $config) {}

            public function count(): int
            {
                return $this->reads;
            }

            public function keyRing(): KeyRing
            {
                return $this->config()->keyRing();
            }

            public function databaseSettings(): DatabaseSettings
            {
                $this->reads++;

                return $this->config()->databaseSettings();
            }

            public function systemValues(): array
            {
                return $this->config()->systemValues();
            }

            public function committedSystemValues(): array
            {
                return $this->config()->committedSystemValues();
            }

            public function ownerUid(): int
            {
                return $this->config()->ownerUid();
            }

            public function holdsOnlyLiteralData(): bool
            {
                return $this->config()->holdsOnlyLiteralData();
            }

            public function isWritable(): bool
            {
                return $this->config()->isWritable();
            }

            public function secretStrings(): array
            {
                $this->reads++;

                return $this->config()->secretStrings();
            }

            private function config(): InMemoryDeploymentConfig
            {
                return $this->config ?? throw new DeploymentConfigUnreadable('app/etc/env.php cannot be read.');
            }
        };
    }
}
