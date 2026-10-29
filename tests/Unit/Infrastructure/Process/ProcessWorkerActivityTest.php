<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Infrastructure\Process;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\MagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RunningProcess;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Process\ProcessWorkerActivity;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Security\PatternSecretRedactor;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectRunningProcessFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\FixedMagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\FixedProcessTable;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\InMemoryDeploymentConfig;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\ProbeStoreRoot;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TemporaryDirectory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * Every running `bin/magento` of this store counts as a worker, whatever the command; the tool's own
 * process tree and other stores' commands do not. Start times come from the elapsed seconds, and an
 * unreadable process list is one entry of unknown age.
 */
final class ProcessWorkerActivityTest extends TestCase
{
    private const NOW = '2026-10-29T10:00:00+00:00';

    private ProbeStoreRoot $store;

    protected function setUp(): void
    {
        $this->store = ProbeStoreRoot::create(KeyMaterial::rawKey());
    }

    protected function tearDown(): void
    {
        $this->store->remove();
    }

    public function testListsEveryStoreCommandWithItsStartTime(): void
    {
        $root = $this->store->path;
        $running = $this->activity([
            ['pid' => 100, 'ppid' => 0, 'elapsed' => 300, 'args' => '/usr/bin/php ' . $root . '/bin/magento cron:run'],
            ['pid' => 101, 'ppid' => 0, 'elapsed' => 60, 'args' => 'php bin/magento queue:consumers:start async.operations.all'],
            ['pid' => 102, 'ppid' => 0, 'elapsed' => 7200, 'args' => 'php ./bin/magento indexer:reindex'],
            ['pid' => 103, 'ppid' => 0, 'elapsed' => 10, 'args' => 'php-fpm: pool www'],
            ['pid' => 104, 'ppid' => 0, 'elapsed' => 10, 'args' => 'vim bin/magento.bak'],
        ], $root)->running();

        self::assertSame([
            'pid 100: /usr/bin/php ' . $root . '/bin/magento cron:run',
            'pid 101: php bin/magento queue:consumers:start async.operations.all',
            'pid 102: php ./bin/magento indexer:reindex',
        ], $this->descriptions($running));
        self::assertSame(
            ['2026-10-29T09:55:00+00:00', '2026-10-29T09:59:00+00:00', '2026-10-29T08:00:00+00:00'],
            array_map(static fn(RunningProcess $p): ?string => $p->startedAt()?->format(DATE_ATOM), $running),
        );
    }

    public function testAnotherStoresCommandsAreLeftOut(): void
    {
        $running = $this->activity([
            ['pid' => 100, 'ppid' => 0, 'elapsed' => 300, 'args' => '/usr/bin/php /var/www/other-store/bin/magento cron:run'],
        ], $this->store->path)->running();

        self::assertSame([], $running);
    }

    public function testTheToolsOwnProcessAndItsDescendantsAreLeftOut(): void
    {
        $own = getmypid();
        self::assertIsInt($own);
        $root = $this->store->path;

        $running = $this->activity([
            ['pid' => $own, 'ppid' => 0, 'elapsed' => 30, 'args' => 'php key-rotator.phar rotate --magento-root ' . $root . ' bin/magento'],
            ['pid' => 900001, 'ppid' => $own, 'elapsed' => 2, 'args' => 'php bin/magento cache:clean config'],
            ['pid' => 900002, 'ppid' => 900001, 'elapsed' => 1, 'args' => 'php ' . $root . '/bin/magento cache:clean config'],
            ['pid' => 900003, 'ppid' => 0, 'elapsed' => 1, 'args' => 'php bin/magento cron:run'],
        ], $root)->running();

        self::assertSame(['pid 900003: php bin/magento cron:run'], $this->descriptions($running));
    }

    public function testAStoreReachedThroughASymbolicLinkRecognisesItsResolvedPath(): void
    {
        $links = TemporaryDirectory::create('key-rotator-links');
        try {
            symlink($this->store->path, $links . '/current');
            $running = $this->activity([
                ['pid' => 100, 'ppid' => 0, 'elapsed' => 5, 'args' => 'php ' . $this->store->path . '/bin/magento cron:run'],
                ['pid' => 101, 'ppid' => 0, 'elapsed' => 5, 'args' => 'php ' . $links . '/current/bin/magento cron:run'],
            ], $links . '/current')->running();

            self::assertCount(2, $running);
        } finally {
            TemporaryDirectory::remove($links);
        }
    }

    public function testWithoutElapsedSecondsTheStartTimeIsUnknown(): void
    {
        $running = $this->activity([
            ['pid' => 100, 'ppid' => 0, 'elapsed' => null, 'args' => 'php bin/magento cron:run'],
        ], $this->store->path)->running();

        self::assertCount(1, $running);
        self::assertNull($running[0]->startedAt());
        self::assertTrue($running[0]->startedBefore(new \DateTimeImmutable('2000-01-01')));
    }

    public function testAnUnreadableProcessListIsOneEntryOfUnknownAge(): void
    {
        $running = $this->activity(null, $this->store->path)->running();

        self::assertCount(1, $running);
        self::assertSame(ProcessWorkerActivity::UNAVAILABLE, $running[0]->description());
        self::assertNull($running[0]->startedAt());
    }

    public function testACommandLineIsRedactedAndCutToAReadableLength(): void
    {
        $key = KeyMaterial::base64Key();
        $running = $this->activity([
            ['pid' => 100, 'ppid' => 0, 'elapsed' => 5, 'args' => 'php bin/magento setup:install --key=' . $key . ' ' . str_repeat('--x ', 80)],
        ], $this->store->path)->running();

        $description = $running[0]->description();
        self::assertStringNotContainsString($key, $description);
        self::assertStringContainsString('--key=[redacted]', $description);
        self::assertStringEndsWith('…', $description);
        self::assertLessThan(230, strlen($description));
    }

    /**
     * @param list<array{pid: int, ppid: int, elapsed: int|null, args: string}>|null $processes
     */
    private function activity(?array $processes, string $root): ProcessWorkerActivity
    {
        $config = new InMemoryDeploymentConfig(ProbeStoreRoot::ring(KeyMaterial::rawKey()));

        return new ProcessWorkerActivity(
            new FixedProcessTable($processes),
            new FixedMagentoRoot(new MagentoRoot($root)),
            new MockClock(new \DateTimeImmutable(self::NOW)),
            new DirectRunningProcessFactory(),
            new PatternSecretRedactor($config),
        );
    }

    /**
     * @param list<RunningProcess> $running
     *
     * @return list<string>
     */
    private function descriptions(array $running): array
    {
        return array_map(static fn(RunningProcess $p): string => $p->description(), $running);
    }
}
