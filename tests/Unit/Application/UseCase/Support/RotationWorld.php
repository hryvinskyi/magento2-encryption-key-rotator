<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase\Support;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\MagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeStatus;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueSource;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Preflight\RunPreflight;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Preflight\StateDirectoryPlacement;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Preflight\StoreClaim;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Reencryption\ReencryptColumnValues;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Reencryption\SystemValueReencryption;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate\NewKeyAppender;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate\RotateKey;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate\RotateRequest;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate\RotateResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate\RotationReencryption;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Scan\CiphertextVerifier;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Scan\ScanEncryptedData;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Status\ReportStatus;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\WebTier\WebTierConfirmation;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Cipher;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Ciphertext;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\CiphertextParser;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Plaintext;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\Key;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRingParser;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Crypto\RandomKeyGenerator;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Crypto\SodiumCipher;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\CallLog;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\ClockAdvancingPause;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectCiphertextFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectColumnFindingsFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeyFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeyRingFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeySlotFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectPlaintextFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectPreflightResultFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectReencryptionFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectReencryptionOutcomeFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectRefusalFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectRotateResultFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectRotationRunFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectScanReportFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectScanScopeFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectStatusReportFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectSystemValueChangeFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectSystemValueFindingFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\FixedMagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\FixedRuntimeUser;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\FixedStateDirectory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\FixedWorkerActivity;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\InMemoryDatabase;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\InMemoryDeploymentConfig;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\InMemoryRunRegistry;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\InMemoryRunStore;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\RecordingConfigCacheCleaner;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\RecordingProgress;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\ScriptedWebTierProbe;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\SequentialRunIdGenerator;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TemporaryDirectory;
use Symfony\Component\Clock\MockClock;

/**
 * A store for the use case tests: every port played by its in-memory double, the real cipher, and the
 * real application services wired as the container wires them.
 *
 * The key ring is `[retired placeholder, old key, active key]` (or, when asked, `[old key, old key, active
 * key]`): slot 0 is retired, slot 1 is an old usable key, slot 2 is the key a rotation finds active, so a rotation moves the values of slots 1 and 2 onto
 * the new slot 3. The database seeds two tables of values under slots 1 and 2, one `system` value in each
 * configuration file, and a Magento root on disk with the state directory inside it and outside the
 * document root. Every plaintext the world encrypts is remembered, so a test can check that values decrypt
 * to the same bytes afterwards and that no report carries them.
 */
final class RotationWorld
{
    public const OWNER_UID = 1000;
    public const ENV_PATH = ['payment', 'gateway', 'api_secret'];
    public const COMMITTED_PATH = ['carriers', 'courier', 'password'];

    public readonly MockClock $clock;
    public readonly CallLog $log;
    public readonly InMemoryDatabase $database;
    public readonly InMemoryDeploymentConfig $config;
    public readonly InMemoryRunStore $runs;
    public readonly InMemoryRunRegistry $registry;
    public readonly ScriptedWebTierProbe $probe;
    public readonly FixedWorkerActivity $workers;
    public readonly RecordingConfigCacheCleaner $cache;
    public readonly RecordingProgress $progress;
    public readonly ClockAdvancingPause $pause;
    public readonly Cipher $cipher;
    public readonly KeyRingParser $ringParser;
    public readonly CiphertextParser $ciphertextParser;
    public readonly KeyRing $ringBefore;
    public readonly string $root;
    public readonly string $stateDirectory;

    public readonly CiphertextVerifier $verifier;
    public readonly ScanEncryptedData $scanner;
    public readonly ReencryptColumnValues $columnReencryption;
    public readonly RunPreflight $preflight;
    public readonly StoreClaim $storeClaim;
    public readonly WebTierConfirmation $webTier;
    public readonly RotateKey $rotateKey;
    public readonly ReportStatus $status;

    /**
     * @var array<int, Key> slot => key of the ring before the run
     */
    private array $keys = [];

    /**
     * @var list<string> every plaintext the world encrypted
     */
    private array $plaintexts = [];

    /**
     * @var array<string, string> `table#id` => plaintext of the value seeded there
     */
    private array $seeded = [];

    /**
     * @param int  $runtimeUid      the user id the tool runs as
     * @param bool $usableFirstSlot whether slot 0 holds a usable key instead of a placeholder, so the ring
     *                              is `[old key, old key, active key]`
     */
    public function __construct(int $runtimeUid = self::OWNER_UID, bool $usableFirstSlot = false)
    {
        $this->clock = new MockClock('2026-10-29 10:00:00', 'UTC');
        $this->log = new CallLog();
        $keys = new DirectKeyFactory();
        $slots = new DirectKeySlotFactory();
        $rings = new DirectKeyRingFactory();
        $this->cipher = new SodiumCipher(new DirectCiphertextFactory(), new DirectPlaintextFactory());
        $this->ringParser = new KeyRingParser($slots, $rings);
        $this->ciphertextParser = new CiphertextParser(new DirectCiphertextFactory());

        $firstSlot = $usableFirstSlot ? KeyMaterial::base64Key() : KeyMaterial::placeholder();
        $oldKey = KeyMaterial::base64Key();
        $activeKey = KeyMaterial::base64Key();
        $this->ringBefore = $this->ringParser->parse($firstSlot . "\n" . $oldKey . "\n" . $activeKey);
        $this->keys = [1 => new Key($oldKey), 2 => new Key($activeKey)];
        if ($usableFirstSlot) {
            $this->keys[0] = new Key($firstSlot);
        }

        $this->database = new InMemoryDatabase(log: $this->log);
        $this->config = new InMemoryDeploymentConfig(
            $this->ringBefore,
            [new SystemValue(self::ENV_PATH, $this->ciphertext('env secret', 2), SystemValueSource::Env)],
            [new SystemValue(self::COMMITTED_PATH, $this->ciphertext('committed secret', 1), SystemValueSource::Committed)],
            self::OWNER_UID,
            log: $this->log,
        );
        $this->runs = new InMemoryRunStore(log: $this->log);
        $this->registry = new InMemoryRunRegistry(log: $this->log);
        $this->probe = new ScriptedWebTierProbe(log: $this->log);
        $this->workers = new FixedWorkerActivity();
        $this->cache = new RecordingConfigCacheCleaner(log: $this->log);
        $this->progress = new RecordingProgress();

        $this->root = TemporaryDirectory::create('key-rotator-use-case');
        mkdir($this->root . '/app/etc', 0700, true);
        mkdir($this->root . '/pub', 0700, true);
        touch($this->root . '/' . MagentoRoot::DEPLOYMENT_CONFIG);
        $this->stateDirectory = $this->root . '/var/encryption-key-rotation';

        $refusals = new DirectRefusalFactory();
        $verifier = new CiphertextVerifier($this->ciphertextParser, $this->cipher, $keys);
        $this->verifier = $verifier;
        $this->scanner = new ScanEncryptedData(
            $this->config,
            $this->database,
            $this->database,
            $verifier,
            new DirectColumnFindingsFactory(),
            new DirectSystemValueFindingFactory(),
            new DirectScanReportFactory(),
            $this->progress,
            $this->clock,
        );
        $this->columnReencryption = new ReencryptColumnValues(
            $this->database,
            $this->database,
            $this->database,
            $this->database,
            $this->ciphertextParser,
            $this->cipher,
            new DirectReencryptionFactory(),
            new DirectReencryptionOutcomeFactory(),
            $this->progress,
        );
        $this->preflight = new RunPreflight(
            $this->config,
            new FixedRuntimeUser($runtimeUid),
            new FixedMagentoRoot(new MagentoRoot($this->root)),
            new FixedStateDirectory($this->stateDirectory),
            new StateDirectoryPlacement($refusals),
            $this->workers,
            $refusals,
            new DirectPreflightResultFactory(),
        );
        $this->storeClaim = new StoreClaim($this->registry, new FixedStateDirectory($this->stateDirectory), $refusals);
        $this->pause = new ClockAdvancingPause($this->clock);
        $this->webTier = new WebTierConfirmation($this->probe, $this->progress, $this->clock, $this->pause);
        $results = new DirectRotateResultFactory();
        $this->rotateKey = new RotateKey(
            $this->runs,
            $this->config,
            $this->preflight,
            $this->storeClaim,
            new SequentialRunIdGenerator(),
            new NewKeyAppender(
                $this->runs,
                $this->config,
                $this->config,
                new RandomKeyGenerator($keys),
                $keys,
                $slots,
                $rings,
                new DirectRotationRunFactory(),
                $refusals,
                $this->progress,
                $this->clock,
            ),
            $this->webTier,
            $this->scanner,
            new RotationReencryption(
                $this->columnReencryption,
                new SystemValueReencryption($this->config, $this->config, $this->cipher, new DirectSystemValueChangeFactory()),
                $this->cache,
                $this->scanner,
                $this->runs,
                $keys,
                new DirectScanScopeFactory(),
                $results,
                $this->progress,
                $this->clock,
            ),
            $this->database,
            $keys,
            new DirectScanScopeFactory(),
            $results,
            $refusals,
            $this->progress,
            $this->clock,
        );
        $this->status = new ReportStatus($this->runs, $this->config, new DirectStatusReportFactory());
    }

    /**
     * Seeds the default tables: `core_config_data` with three values under the old key and two under the
     * active key, `oauth_consumer` with two values under the active key and a plain text value.
     */
    public function seedDefault(): self
    {
        $this->database->createTable('core_config_data', ['config_id'], ['value']);
        foreach ([1 => 1, 2 => 1, 3 => 1, 4 => 2, 5 => 2] as $id => $index) {
            $this->seed('core_config_data', $id, 'value', sprintf('config secret %d', $id), $index, 'config_id');
        }
        $this->database->createTable('oauth_consumer', ['entity_id'], ['secret'], ['updated_at']);
        $this->seed('oauth_consumer', 1, 'secret', 'consumer secret 1', 2);
        $this->seed('oauth_consumer', 2, 'secret', 'consumer secret 2', 2);
        $this->database->insert('oauth_consumer', ['entity_id' => 3, 'secret' => 'not encrypted', 'updated_at' => 0]);

        return $this;
    }

    /**
     * Inserts a row whose column holds the plaintext encrypted under that slot of the ring before the run.
     */
    public function seed(string $table, int $id, string $column, string $plaintext, int $index, string $keyColumn = 'entity_id'): string
    {
        $raw = $this->encrypt($plaintext, $index);
        $this->database->insert($table, [$keyColumn => $id, $column => $raw, 'updated_at' => 0]);
        $this->seeded[$table . '#' . $id] = $plaintext;

        return $raw;
    }

    /**
     * The plaintext under that slot, as the store would have written it.
     */
    public function encrypt(string $plaintext, int $index, ?Key $key = null): string
    {
        return $this->ciphertext($plaintext, $index, $key)->toString();
    }

    public function ciphertext(string $plaintext, int $index, ?Key $key = null): Ciphertext
    {
        $this->plaintexts[] = $plaintext;

        return $this->cipher->encrypt(new Plaintext($plaintext), $index, $key ?? $this->key($index));
    }

    /**
     * The key of a slot of the ring before the run.
     */
    public function key(int $index): Key
    {
        return $this->keys[$index] ?? throw new \LogicException(sprintf('The ring before the run holds no key in slot %d.', $index));
    }

    /**
     * Decrypts a stored value with the key ring the deployment configuration holds now.
     */
    public function decryptNow(string $raw): ?string
    {
        $ciphertext = $this->ciphertextParser->parse($raw);
        if ($ciphertext === null) {
            return null;
        }
        $key = $this->config->keyRing()->slot($ciphertext->keyIndex())?->key(new DirectKeyFactory());

        return $key === null ? null : $this->cipher->decrypt($ciphertext, $key)?->bytes();
    }

    /**
     * @return array<string, string> `table#id` => plaintext seeded there
     */
    public function seeded(): array
    {
        return $this->seeded;
    }

    /**
     * @return list<string> every plaintext the world encrypted
     */
    public function plaintexts(): array
    {
        return $this->plaintexts;
    }

    public function value(string $table, int $id, string $column, string $keyColumn = 'entity_id'): string
    {
        $value = $this->database->value($table, [$keyColumn => $id], $column);

        return is_string($value) ? $value : throw new \LogicException(sprintf('No text in %s#%d.%s.', $table, $id, $column));
    }

    public function probeSettings(int $waitSeconds = 30, bool $skipped = false): ProbeSettings
    {
        return new ProbeSettings('unix:///run/php-fpm.sock', null, null, ProbeSettings::DEFAULT_DOCROOT, true, $waitSeconds, $skipped);
    }

    public function request(
        bool $dryRun = false,
        ?string $rawKey = null,
        int $batchSize = RotateRequest::DEFAULT_BATCH_SIZE,
        bool $ignoreWorkers = false,
        bool $allowOtherUser = false,
        ?ProbeSettings $probeSettings = null,
    ): RotateRequest {
        return new RotateRequest($dryRun, $rawKey, $batchSize, $ignoreWorkers, $allowOtherUser, $probeSettings ?? $this->probeSettings());
    }

    public function rotate(?RotateRequest $request = null): RotateResult
    {
        return $this->rotateKey->rotate($request ?? $this->request());
    }

    public function differs(): ProbeOutcome
    {
        return new ProbeOutcome(ProbeStatus::Differs, 'The web tier holds another key ring.');
    }

    public function matches(): ProbeOutcome
    {
        return new ProbeOutcome(ProbeStatus::Matches, 'The web tier holds the expected key ring.');
    }

    public function cleanUp(): void
    {
        TemporaryDirectory::remove($this->root);
    }
}
