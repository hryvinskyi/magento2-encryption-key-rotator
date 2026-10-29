<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\EndToEnd;

use Hryvinskyi\EncryptionKeyRotator\Cli\ExitCode;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\BuiltInWebServer;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\EndToEndStore;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\FastCgiServer;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\Nested;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Process\Process;

/**
 * The whole life of a rotation, run the way an operator runs it: `bin/key-rotator` in a process of its
 * own, with the container it compiles, against a store on disk and a real database, the web tier probed
 * over HTTP (PHP's built-in server) or FastCGI (a real PHP-FPM pool).
 *
 * scan → rotate → an application write under the new key → retire → rollback → purge; a rotation the
 * web tier has not confirmed waits and resumes; a rollback killed midway is finished by running it again;
 * a store command still running refuses the rotation. Nothing the tool prints ever holds a plaintext, a
 * key or the database password.
 */
final class RotationLifecycleTest extends TestCase
{
    private ?EndToEndStore $store = null;

    private ?BuiltInWebServer $web = null;

    private ?FastCgiServer $fpm = null;

    /**
     * @var list<string> everything the tool printed, step by step
     */
    private array $transcript = [];

    protected function tearDown(): void
    {
        $this->web?->stop();
        $this->fpm?->stop();
        $this->store?->remove();
    }

    public function testTheLifecycleOverHttp(): void
    {
        $store = $this->store = EndToEndStore::create();
        $this->web = BuiltInWebServer::start($store->root . '/pub');
        $probe = ['--probe-url=' . $this->web->baseUrl()];

        $this->refusesWhileAStoreCommandRuns($store, $probe);
        $this->lifecycle($store, $probe);
        $this->assertNothingSecretWasPrinted($store);
    }

    public function testTheLifecycleOverFastCgi(): void
    {
        $store = $this->store = EndToEndStore::create();
        // A pool that reads every file afresh, as one reloaded after every key ring change does.
        $this->fpm = FastCgiServer::start(['php_admin_flag[opcache.enable] = off']);

        $this->lifecycle($store, ['--probe-fcgi=' . $this->fpm->address()]);
        $this->assertNothingSecretWasPrinted($store);
    }

    public function testARotationTheWebTierHasNotConfirmedWaitsAndResumesOnceThePoolReloaded(): void
    {
        $store = $this->store = EndToEndStore::create();
        // Opcache keeps every file it compiled: after the key ring write the pool still holds the old ring.
        $fpm = $this->fpm = FastCgiServer::start();
        $probe = ['--probe-fcgi=' . $fpm->address()];

        $waiting = $this->tool($store, ['rotate', '--yes', '--probe-wait=2', ...$probe]);

        self::assertSame(ExitCode::WAITING, $waiting->getExitCode(), $this->last());
        self::assertStringContainsString('Rotation: awaiting_web_tier', $waiting->getOutput());
        self::assertCount(3, $store->ring()->slots());
        $status = $this->statusOf($store);
        self::assertSame('key_added', $status['state']);

        $fpm->reload();
        $resumed = $this->tool($store, ['rotate', '--yes', '--probe-wait=30', ...$probe]);

        self::assertSame(ExitCode::DONE, $resumed->getExitCode(), $this->last());
        self::assertStringContainsString('Run: ' . $status['run_id'] . ' (reencrypted)', $resumed->getOutput());
        $this->assertEveryValueUnder($store, 2);
        $this->assertNothingSecretWasPrinted($store);
    }

    public function testARollbackKilledMidwayIsFinishedByRunningItAgain(): void
    {
        $store = $this->store = EndToEndStore::create();
        $this->web = BuiltInWebServer::start($store->root . '/pub');
        $probe = ['--probe-url=' . $this->web->baseUrl()];
        $ringBefore = $store->ring()->fingerprint();
        $seeded = $store->seededValues();
        self::assertSame(ExitCode::DONE, $this->tool($store, ['rotate', '--yes', ...$probe])->getExitCode(), $this->last());

        $store->killToolOnNextCacheClean();
        $killed = $this->tool($store, ['rollback', '--yes', ...$probe]);

        self::assertFalse($killed->isSuccessful(), $this->last());
        self::assertFileDoesNotExist($store->root . '/var/kill-on-cache-clean', 'The rollback never reached its first cache clean.');
        self::assertSame('rolling_back', $this->statusOf($store)['state']);

        $retire = $this->tool($store, ['retire', '--yes', ...$probe]);
        self::assertSame(ExitCode::REFUSED, $retire->getExitCode(), $this->last());
        self::assertStringContainsString('[rollback_in_progress]', $retire->getOutput());

        $finished = $this->tool($store, ['rollback', '--yes', ...$probe]);
        self::assertSame(ExitCode::DONE, $finished->getExitCode(), $this->last());
        self::assertStringContainsString('Rollback: rolled_back', $finished->getOutput());
        self::assertSame($ringBefore, $store->ring()->fingerprint());
        self::assertSame($seeded, $store->currentValues());
        self::assertSame(ExitCode::DONE, $this->tool($store, ['purge', '--yes'])->getExitCode(), $this->last());
        $this->assertNothingSecretWasPrinted($store);
    }

    /**
     * @param list<string> $probe
     */
    private function refusesWhileAStoreCommandRuns(EndToEndStore $store, array $probe): void
    {
        $ring = $store->ring()->fingerprint();
        $consumer = $store->startStoreCommand(60);
        try {
            // The process list counts whole seconds: the command must be older than the moment the tool checks.
            usleep(2_100_000);
            self::assertTrue($consumer->isRunning(), $consumer->getErrorOutput());

            $refused = $this->tool($store, ['rotate', '--yes', ...$probe]);

            self::assertSame(ExitCode::REFUSED, $refused->getExitCode(), $this->last());
            self::assertStringContainsString('[workers_running]', $refused->getOutput());
            self::assertStringContainsString('queue:consumers:start', $refused->getOutput());
            self::assertSame($ring, $store->ring()->fingerprint());
            self::assertSame([], glob($store->stateDirectory() . '/*', GLOB_ONLYDIR), 'A run was started.');
        } finally {
            $consumer->stop(0);
        }
    }

    /**
     * scan, rotate, an application write, retire, rollback and purge, each checked against the store.
     *
     * @param list<string> $probe
     */
    private function lifecycle(EndToEndStore $store, array $probe): void
    {
        $seeded = $store->seededValues();
        $ringBefore = $store->ring();
        $timestamps = $store->customerTimestamps();
        $systemPlaintext = $store->decrypt($store->systemValue());
        self::assertNotNull($systemPlaintext);

        // 1. The scan shows what the seed holds.
        $scan = $this->tool($store, ['scan', '--format=json']);
        self::assertSame(ExitCode::DONE, $scan->getExitCode(), $this->last());
        $report = Nested::json($scan->getOutput());
        $columns = array_column(Nested::array($report, 'columns'), 'indices', 'column');
        self::assertEqualsCanonicalizing(
            ['core_config_data.value', 'customer_entity.rp_token', 'oauth_consumer.secret', 'composite_secret.secret', 'binary_secret.raw_secret', 'binary_secret.blob_secret'],
            array_keys($columns),
        );
        self::assertSame([['index' => 0, 'counts' => ['retired_key' => 1]], ['index' => 1, 'counts' => ['verified' => 3]]], $columns['core_config_data.value']);
        self::assertSame([['index' => 1, 'counts' => ['verified' => 2]]], $columns['composite_secret.secret']);
        $byIndex = array_column(Nested::array($report, 'totals'), null, 'index');
        self::assertSame(count($seeded) + 1, Nested::value($byIndex, 1, 'verified'), 'every seeded value and the system value');
        self::assertSame(1, Nested::value($byIndex, 0, 'retired_key'));
        self::assertSame([['source' => 'env', 'path' => 'default/' . EndToEndStore::SYSTEM_PATH, 'key_index' => 1, 'verdict' => 'verified']], Nested::value($report, 'system_values'));

        // 2. The rotation moves every value under slot 1 onto the new slot 2.
        $rotate = $this->tool($store, ['rotate', '--yes', ...$probe]);
        self::assertSame(ExitCode::DONE, $rotate->getExitCode(), $this->last());
        $rotated = $store->ring();
        self::assertCount(3, $rotated->slots());
        self::assertSame($ringBefore->slot(0)?->raw(), $rotated->slot(0)?->raw());
        self::assertSame($ringBefore->slot(1)?->raw(), $rotated->slot(1)?->raw());
        $this->assertEveryValueUnder($store, 2);
        self::assertStringStartsWith('2:3:', $store->systemValue());
        self::assertSame($systemPlaintext, $store->decrypt($store->systemValue()));
        self::assertSame($store->seededRetiredValue(), $store->retiredValue());
        self::assertSame($timestamps, $store->customerTimestamps());
        self::assertContains('cache:clean config', $store->storeCommands());
        self::assertStringContainsString('Next:', $rotate->getOutput());

        // 3. The application writes a value under the new key.
        $written = $store->applicationWrite('e2e/application/write', 'application secret ' . bin2hex(random_bytes(4)), 2);
        $writtenPlaintext = $store->decrypt($written);

        // 4. Retiring replaces slot 1 by a placeholder and keeps its key in the run directory.
        $retire = $this->tool($store, ['retire', '--yes', ...$probe]);
        self::assertSame(ExitCode::DONE, $retire->getExitCode(), $this->last());
        $retired = $store->ring();
        self::assertStringStartsWith('invalid', (string) $retired->slot(1)?->raw());
        self::assertSame(32, strlen((string) $retired->slot(1)?->raw()));
        self::assertSame($ringBefore->slot(0)?->raw(), $retired->slot(0)?->raw());
        self::assertSame($rotated->slot(2)?->raw(), $retired->slot(2)?->raw());
        $status = $this->statusOf($store);
        self::assertSame('retired', $status['state']);
        $runDirectory = $store->stateDirectory() . '/' . $status['run_id'];
        self::assertFileExists($runDirectory . '/keys.json');
        self::assertSame(0600, fileperms($runDirectory . '/keys.json') & 0777);

        // 5. The rollback restores the ring and the bytes from before the run; the application's value moves onto slot 1.
        $rollback = $this->tool($store, ['rollback', '--yes', ...$probe]);
        self::assertSame(ExitCode::DONE, $rollback->getExitCode(), $this->last());
        self::assertSame($ringBefore->fingerprint(), $store->ring()->fingerprint());
        self::assertSame($seeded, $store->currentValues());
        $moved = $store->valueAt('e2e/application/write');
        self::assertStringStartsWith('1:3:', $moved);
        self::assertSame($writtenPlaintext, $store->decrypt($moved));
        self::assertStringStartsWith('1:3:', $store->systemValue());
        self::assertSame($systemPlaintext, $store->decrypt($store->systemValue()));
        self::assertSame($timestamps, $store->customerTimestamps());

        // 6. The purge drops the journal and the run directory.
        $purge = $this->tool($store, ['purge', '--yes']);
        self::assertSame(ExitCode::DONE, $purge->getExitCode(), $this->last());
        self::assertFalse($store->journalExists());
        self::assertDirectoryDoesNotExist($runDirectory);
        self::assertSame($store->seededRetiredValue(), $store->retiredValue());
    }

    private function assertEveryValueUnder(EndToEndStore $store, int $index): void
    {
        $plaintexts = $store->plaintextsByLabel();
        foreach ($store->currentValues() as $label => $raw) {
            self::assertStringStartsWith($index . ':3:', $raw, $label);
            self::assertSame($plaintexts[$label], $store->decrypt($raw), $label);
        }
    }

    private function assertNothingSecretWasPrinted(EndToEndStore $store): void
    {
        $transcript = implode("\n", $this->transcript);
        foreach ($store->secrets() as $secret) {
            self::assertStringNotContainsString($secret, $transcript);
        }
    }

    /**
     * @return array{run_id: string, state: string}
     */
    private function statusOf(EndToEndStore $store): array
    {
        $process = $this->tool($store, ['status', '--format=json']);
        self::assertSame(ExitCode::DONE, $process->getExitCode(), $this->last());
        $status = Nested::json($process->getOutput());

        return ['run_id' => Nested::string($status, 'run_id'), 'state' => Nested::string($status, 'state')];
    }

    /**
     * @param list<string> $arguments
     */
    private function tool(EndToEndStore $store, array $arguments): Process
    {
        $process = $store->tool([...$arguments, '--magento-root=' . $store->root]);
        $this->transcript[] = sprintf("$ %s\n[exit %s]\n%s\n%s", implode(' ', $arguments), var_export($process->getExitCode(), true), $process->getOutput(), $process->getErrorOutput());

        return $process;
    }

    private function last(): string
    {
        return (string) end($this->transcript);
    }
}
