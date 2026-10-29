<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Support;

use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Ciphertext;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;
use Symfony\Component\Process\Exception\ProcessSignaledException;
use Symfony\Component\Process\Process;

/**
 * A store for the end-to-end tests: a scratch Magento root and a database of its own, as a real store
 * holds them, and the tool run against it as an operator runs it, through `bin/key-rotator` in a
 * process of its own.
 *
 * - `app/etc/env.php` holds a ring with a retired slot 0 and an active slot 1, the table prefix `t_`, the
 *   connection to the test database and one encrypted `system` value;
 * - `app/etc/config.php` holds no encrypted value; `pub/` is the document root; `bin/magento` is a stand-in
 *   that records every call (see `tests/Fixtures/EndToEnd/magento`);
 * - the database holds values under slot 1 in tables of the shapes a store has (single and composite
 *   keys, an auto-updated timestamp, binary columns, a column too short for a ciphertext), one value
 *   under the retired slot 0, the cron schedule, and plain values.
 *
 * Every plaintext and every key the store made is remembered, so a test can check that none of them
 * ever reaches the tool's output.
 */
final class EndToEndStore
{
    public const PREFIX = 't_';
    public const SYSTEM_PATH = 'payment/gateway/api_secret';

    /**
     * @var array<string, array{sql: string, parameters: list<int|string>, plaintext: string, raw: string}>
     *      label => how to read the seeded value back, its plaintext and its bytes as seeded
     */
    private array $seeded = [];

    /**
     * @var list<string>
     */
    private array $plaintexts = [];

    /**
     * @var list<string> every ring entry the store held
     */
    private array $keys = [];

    private string $retiredValue = '';

    private function __construct(
        public readonly string $root,
        public readonly TestDatabase $database,
    ) {}

    public static function create(): self
    {
        $root = TemporaryDirectory::create('key-rotator-e2e');
        foreach (['app/etc', 'pub', 'var', 'bin'] as $directory) {
            mkdir($root . '/' . $directory, 0755, true);
        }
        $fake = dirname(__DIR__) . '/Fixtures/EndToEnd/magento';
        if (!copy($fake, $root . '/bin/magento') || !chmod($root . '/bin/magento', 0755)) {
            throw new \RuntimeException('The stand-in bin/magento could not be put in place.');
        }
        file_put_contents($root . '/app/etc/config.php', "<?php\nreturn ['modules' => ['Magento_Store' => 1]];\n");

        $store = new self($root, TestDatabase::create(self::PREFIX));
        $store->writeDeploymentConfig(KeyMaterial::placeholder(), KeyMaterial::base64Key());
        $store->seed();

        return $store;
    }

    /**
     * Runs the tool with these arguments and waits for it; a tool killed by a signal is a result too.
     *
     * @param list<string> $arguments
     */
    public function tool(array $arguments, float $timeout = 300): Process
    {
        $process = new Process([PHP_BINARY, dirname(__DIR__, 2) . '/bin/key-rotator', ...$arguments], $this->root, null, null, $timeout);
        try {
            $process->run();
        } catch (ProcessSignaledException) {
            // The process object still tells how it ended and what it wrote.
        }

        return $process;
    }

    /**
     * The key ring `app/etc/env.php` holds now.
     */
    public function ring(): KeyRing
    {
        $ring = CryptoServices::shared()->ringParser()->parse($this->cryptKey());
        foreach ($ring->slots() as $slot) {
            if (!in_array($slot->raw(), $this->keys, true)) {
                $this->keys[] = $slot->raw();
            }
        }

        return $ring;
    }

    /**
     * The plaintext of a stored value under the ring `app/etc/env.php` holds now, or null when no slot
     * of it decrypts the value.
     */
    public function decrypt(string $raw): ?string
    {
        $crypto = CryptoServices::shared();
        $ciphertext = $crypto->ciphertextParser()->parse($raw);
        $key = $ciphertext === null ? null : $this->ring()->slot($ciphertext->keyIndex())?->key($crypto->keys());

        return $ciphertext === null || $key === null ? null : $crypto->cipher()->decrypt($ciphertext, $key)?->bytes();
    }

    /**
     * @return array<string, string> label => plaintext of every value seeded under slot 1
     */
    public function plaintextsByLabel(): array
    {
        return array_map(static fn(array $value): string => $value['plaintext'], $this->seeded);
    }

    /**
     * @return array<string, string> label => the bytes the database holds now
     */
    public function currentValues(): array
    {
        $values = [];
        foreach ($this->seeded as $label => $value) {
            $current = $this->database->value($value['sql'], $value['parameters']);
            $values[$label] = is_string($current) ? $current : throw new \RuntimeException(sprintf('No value at %s.', $label));
        }

        return $values;
    }

    /**
     * @return array<string, string> label => the bytes as seeded
     */
    public function seededValues(): array
    {
        return array_map(static fn(array $value): string => $value['raw'], $this->seeded);
    }

    /**
     * The bytes of the value under the retired slot 0, which no step may touch.
     */
    public function retiredValue(): string
    {
        $current = $this->database->value(sprintf('SELECT value FROM %s WHERE path = ?', $this->table('core_config_data')), ['retired/slot/value']);

        return is_string($current) ? $current : '';
    }

    public function seededRetiredValue(): string
    {
        return $this->retiredValue;
    }

    /**
     * The encrypted `system` value of `app/etc/env.php`, as the file holds it now.
     */
    public function systemValue(): string
    {
        return Nested::string(ScratchMagentoRoot::evaluate($this->deploymentConfigFile()), 'system', 'default', ...explode('/', self::SYSTEM_PATH));
    }

    /**
     * Writes a value the way the store's application does: encrypted under the given slot of the ring
     * `app/etc/env.php` holds now.
     *
     * @return string the bytes written
     */
    public function applicationWrite(string $path, string $plaintext, int $index): string
    {
        $raw = $this->encrypt($plaintext, $index);
        $this->database->connection()->prepare(sprintf('INSERT INTO %s (path, value) VALUES (?, ?)', $this->table('core_config_data')))->execute([$path, $raw]);

        return $raw;
    }

    public function valueAt(string $path): string
    {
        $value = $this->database->value(sprintf('SELECT value FROM %s WHERE path = ?', $this->table('core_config_data')), [$path]);

        return is_string($value) ? $value : throw new \RuntimeException(sprintf('No value at %s.', $path));
    }

    /**
     * @return list<string> the `updated_at` of every customer row, which re-encrypting must leave alone
     */
    public function customerTimestamps(): array
    {
        return array_map(
            static fn(array $row): string => is_scalar($row['updated_at']) ? (string) $row['updated_at'] : '',
            $this->database->select(sprintf('SELECT updated_at FROM %s ORDER BY entity_id', $this->table('customer_entity'))),
        );
    }

    public function journalExists(): bool
    {
        $count = $this->database->value(
            'SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?',
            [$this->database->name(), $this->table('encryption_key_rotation_journal')],
        );

        return is_numeric($count) && (int) $count === 1;
    }

    public function stateDirectory(): string
    {
        return $this->root . '/var/encryption-key-rotation';
    }

    /**
     * @return list<string> the store's commands the tool ran, in order
     */
    public function storeCommands(): array
    {
        $log = @file_get_contents($this->root . '/var/bin-magento.log');

        return $log === false ? [] : array_values(array_filter(explode("\n", $log), static fn(string $line): bool => $line !== ''));
    }

    /**
     * Makes the next `cache:clean config` kill the tool that runs it.
     */
    public function killToolOnNextCacheClean(): void
    {
        touch($this->root . '/var/kill-on-cache-clean');
    }

    /**
     * Starts a long-running store command, as cron or a queue consumer is, holding the ring of now.
     */
    public function startStoreCommand(int $seconds): Process
    {
        $process = new Process([PHP_BINARY, $this->root . '/bin/magento', 'queue:consumers:start', 'e2e', (string) $seconds], $this->root);
        $process->start();

        return $process;
    }

    public function deploymentConfigFile(): string
    {
        return $this->root . '/app/etc/env.php';
    }

    /**
     * Every plaintext, every ring entry and the database password: what the tool must never print.
     *
     * @return list<string>
     */
    public function secrets(): array
    {
        $this->ring();

        return [...$this->plaintexts, ...$this->keys, $this->database->settings()->password()];
    }

    public function remove(): void
    {
        $this->database->drop();
        TemporaryDirectory::remove($this->root);
    }

    private function cryptKey(): string
    {
        return Nested::string(ScratchMagentoRoot::evaluate($this->deploymentConfigFile()), 'crypt', 'key');
    }

    private function writeDeploymentConfig(string $retired, string $active): void
    {
        $this->keys = [$retired, $active];
        $settings = $this->database->settings();
        $config = [
            'crypt' => ['key' => $retired . "\n" . $active],
            'db' => [
                'table_prefix' => self::PREFIX,
                'connection' => [
                    'default' => [
                        'host' => $settings->host(),
                        'dbname' => $settings->dbname(),
                        'username' => $settings->user(),
                        'password' => $settings->password(),
                        'model' => 'mysql4',
                        'engine' => 'innodb',
                        'initStatements' => 'SET NAMES utf8;',
                        'active' => '1',
                    ],
                ],
            ],
            'MAGE_MODE' => 'production',
        ];
        $this->put($config);
        // The system value is encrypted under the ring just written, so it is written in a second step.
        $config['system'] = ['default' => ['payment' => ['gateway' => ['api_secret' => $this->encrypt('env system secret ' . bin2hex(random_bytes(4)), 1)]]]];
        $this->put($config);
    }

    /**
     * @param array<string, mixed> $config
     */
    private function put(array $config): void
    {
        file_put_contents($this->deploymentConfigFile(), "<?php\nreturn " . var_export($config, true) . ";\n");
        chmod($this->deploymentConfigFile(), 0640);
    }

    private function seed(): void
    {
        $this->database->exec(
            sprintf('CREATE TABLE %s (config_id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, path VARCHAR(255) NOT NULL, value TEXT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4', $this->table('core_config_data')),
            sprintf('CREATE TABLE %s (entity_id INT UNSIGNED NOT NULL PRIMARY KEY, rp_token VARCHAR(128) NULL, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4', $this->table('customer_entity')),
            sprintf('CREATE TABLE %s (entity_id INT UNSIGNED NOT NULL PRIMARY KEY, secret VARCHAR(128) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4', $this->table('oauth_consumer')),
            sprintf('CREATE TABLE %s (store_id SMALLINT UNSIGNED NOT NULL, code VARCHAR(32) NOT NULL, secret TEXT NOT NULL, PRIMARY KEY (store_id, code)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4', $this->table('composite_secret')),
            sprintf('CREATE TABLE %s (id INT UNSIGNED NOT NULL PRIMARY KEY, raw_secret VARBINARY(255) NULL, blob_secret BLOB NULL) ENGINE=InnoDB', $this->table('binary_secret')),
            sprintf('CREATE TABLE %s (id INT UNSIGNED NOT NULL PRIMARY KEY, short_code VARCHAR(32) NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4', $this->table('short_value')),
            sprintf('CREATE TABLE %s (schedule_id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, job_code VARCHAR(255) NOT NULL, status VARCHAR(7) NOT NULL, executed_at TIMESTAMP NULL) ENGINE=InnoDB', $this->table('cron_schedule')),
        );

        foreach (['payment/gateway/password', 'carrier/courier/api_key', 'newsletter/sender/secret'] as $path) {
            $this->insert('core_config_data ' . $path, 'core_config_data', ['path' => $path], 'value');
        }
        $this->retiredValue = $this->ciphertextUnder(0)->toString();
        $this->row('core_config_data', ['path' => 'retired/slot/value', 'value' => $this->retiredValue]);
        $this->row('core_config_data', ['path' => 'web/unsecure/base_url', 'value' => 'https://store.example.test/']);
        foreach ([1, 2] as $id) {
            $this->insert('customer_entity ' . $id, 'customer_entity', ['entity_id' => $id, 'updated_at' => '2026-01-01 00:00:00'], 'rp_token');
        }
        $this->row('customer_entity', ['entity_id' => 3, 'rp_token' => null, 'updated_at' => '2026-01-01 00:00:00']);
        $this->insert('oauth_consumer 1', 'oauth_consumer', ['entity_id' => 1], 'secret');
        foreach ([[0, 'default'], [1, 'store_view']] as [$store, $code]) {
            $this->insert(sprintf('composite_secret %d/%s', $store, $code), 'composite_secret', ['store_id' => $store, 'code' => $code], 'secret');
        }
        $this->insert('binary_secret raw', 'binary_secret', ['id' => 1, 'blob_secret' => null], 'raw_secret');
        $this->insert('binary_secret blob', 'binary_secret', ['id' => 2, 'raw_secret' => null], 'blob_secret');
        $this->row('short_value', ['id' => 1, 'short_code' => '1:3:c2hvcnQ=']);
        $this->row('cron_schedule', ['job_code' => 'sales_clean_quotes', 'status' => 'success', 'executed_at' => '2026-01-01 00:00:00']);
    }

    /**
     * Inserts a row whose column holds a fresh plaintext encrypted under slot 1 and remembers how to
     * read it back.
     *
     * @param array<string, int|string|null> $key the row's other columns, its key among them
     */
    private function insert(string $label, string $table, array $key, string $column): void
    {
        $plaintext = sprintf('e2e secret %s %s', $label, bin2hex(random_bytes(6)));
        $raw = $this->encrypt($plaintext, 1);
        $this->row($table, $key + [$column => $raw]);

        $conditions = [];
        $parameters = [];
        foreach ($key as $name => $value) {
            if ($value === null || $name === 'updated_at') {
                continue;
            }
            $conditions[] = $name . ' = ?';
            $parameters[] = $value;
        }
        $this->seeded[$label] = [
            'sql' => sprintf('SELECT %s FROM %s WHERE %s', $column, $this->table($table), implode(' AND ', $conditions)),
            'parameters' => $parameters,
            'plaintext' => $plaintext,
            'raw' => $raw,
        ];
    }

    /**
     * @param array<string, int|string|null> $values
     */
    private function row(string $table, array $values): void
    {
        $this->database->connection()->prepare(sprintf(
            'INSERT INTO %s (%s) VALUES (%s)',
            $this->table($table),
            implode(', ', array_keys($values)),
            implode(', ', array_fill(0, count($values), '?')),
        ))->execute(array_values($values));
    }

    private function encrypt(string $plaintext, int $index): string
    {
        $this->plaintexts[] = $plaintext;
        $crypto = CryptoServices::shared();
        $key = $this->ring()->slot($index)?->key($crypto->keys()) ?? throw new \LogicException(sprintf('Slot %d of the ring holds no usable key.', $index));

        return $crypto->cipher()->encrypt($crypto->plaintexts()->create($plaintext), $index, $key)->toString();
    }

    /**
     * A well-formed ciphertext under a slot whose key is gone: the store can no longer read it, and the
     * tool must leave it alone.
     */
    private function ciphertextUnder(int $index): Ciphertext
    {
        $crypto = CryptoServices::shared();

        return $crypto->cipher()->encrypt($crypto->plaintexts()->create('lost ' . bin2hex(random_bytes(4))), $index, $crypto->keys()->create(KeyMaterial::base64Key()));
    }

    private function table(string $name): string
    {
        return self::PREFIX . $name;
    }
}
