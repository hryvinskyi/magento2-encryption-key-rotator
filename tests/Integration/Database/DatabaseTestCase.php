<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\Database;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Reencryption;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RowKey;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\StoredValue;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Ciphertext;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\Key;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\CryptoServices;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\DatabaseAdapters;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TestDatabase;
use PHPUnit\Framework\TestCase;

/**
 * A database of its own per test, with the table prefix `m2_`, the adapters wired over it, and real
 * ciphertexts: every value is sealed by the sodium cipher under a fresh key per key index.
 */
abstract class DatabaseTestCase extends TestCase
{
    protected const PREFIX = 'm2_';
    protected const RUN = '0123456789abcdef0123456789abcdef';

    protected TestDatabase $database;

    protected DatabaseAdapters $adapters;

    /**
     * @var array<int, Key>
     */
    private array $keys = [];

    protected function setUp(): void
    {
        $this->database = TestDatabase::create(self::PREFIX);
        $this->adapters = $this->adapters();
    }

    protected function tearDown(): void
    {
        $this->database->drop();
    }

    /**
     * The adapters under test; a test case overrides it to wire other doubles.
     */
    protected function adapters(): DatabaseAdapters
    {
        return new DatabaseAdapters($this->database->deploymentConfig());
    }

    /**
     * A real ciphertext of the plaintext under the key of that index.
     */
    protected function encrypt(int $keyIndex, string $plaintext): Ciphertext
    {
        $crypto = CryptoServices::shared();

        return $crypto->cipher()->encrypt($crypto->plaintexts()->create($plaintext), $keyIndex, $this->key($keyIndex));
    }

    /**
     * What the value decrypts to under the key of its index, or null when it does not.
     */
    protected function decrypt(string $value): ?string
    {
        $crypto = CryptoServices::shared();
        $ciphertext = $crypto->ciphertextParser()->parse($value);
        if ($ciphertext === null) {
            return null;
        }

        return $crypto->cipher()->decrypt($ciphertext, $this->key($ciphertext->keyIndex()))?->bytes();
    }

    /**
     * Re-encrypts a stored value under another key index, as the use case would.
     */
    protected function reencryption(ColumnRef $column, StoredValue $value, int $toIndex): Reencryption
    {
        $plaintext = $this->decrypt($value->raw()) ?? throw new \LogicException('The stored value does not decrypt.');

        return new Reencryption($column, $value->rowKey(), $value->raw(), $this->encrypt($toIndex, $plaintext));
    }

    /**
     * @param array<string, int|string> $key
     */
    protected function rowKey(array $key): RowKey
    {
        return new RowKey($key);
    }

    protected function runId(): RunId
    {
        return new RunId(self::RUN);
    }

    /**
     * Every value a column yields for a key index, batch by batch.
     *
     * @return list<list<StoredValue>>
     */
    protected function batches(ColumnRef $column, int $keyIndex, int $batchSize): array
    {
        $batches = [];
        foreach ($this->adapters->rows->batches($column, $keyIndex, $batchSize) as $batch) {
            $batches[] = $batch;
        }

        return $batches;
    }

    /**
     * The stored value of one column of one row, read by the test's own connection.
     */
    protected function stored(string $table, string $column, string $where, int|string ...$parameters): ?string
    {
        $value = $this->database->value(
            sprintf('SELECT `%s` FROM `%s` WHERE %s', $column, $this->database->table($table), $where),
            array_values($parameters),
        );

        return is_string($value) ? $value : null;
    }

    protected function journalRows(): int
    {
        $count = $this->database->value(sprintf('SELECT COUNT(*) FROM `%s`', $this->database->table('encryption_key_rotation_journal')));

        return is_int($count) ? $count : (int) (is_string($count) ? $count : 0);
    }

    private function key(int $keyIndex): Key
    {
        return $this->keys[$keyIndex] ??= CryptoServices::shared()->keys()->create(KeyMaterial::base64Key());
    }
}
