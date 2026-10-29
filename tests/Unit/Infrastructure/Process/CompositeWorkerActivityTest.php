<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Infrastructure\Process;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\RunningProcess;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Process\CompositeWorkerActivity;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\FixedWorkerActivity;
use PHPUnit\Framework\TestCase;

/**
 * The composite reports what every source reports, in the order of the sources.
 */
final class CompositeWorkerActivityTest extends TestCase
{
    public function testConcatenatesEverySource(): void
    {
        $processes = new FixedWorkerActivity();
        $processes->start('pid 100: php bin/magento cron:run', new \DateTimeImmutable('2026-10-29T09:00:00+00:00'));
        $schedule = new FixedWorkerActivity();
        $schedule->start('job indexer_reindex_all_invalid', null);
        $schedule->start('job sales_clean_quotes', null);

        $running = (new CompositeWorkerActivity([$processes, new FixedWorkerActivity(), $schedule]))->running();

        self::assertSame(
            ['pid 100: php bin/magento cron:run', 'job indexer_reindex_all_invalid', 'job sales_clean_quotes'],
            array_map(static fn(RunningProcess $p): string => $p->description(), $running),
        );
    }

    public function testWithoutSourcesNothingRuns(): void
    {
        self::assertSame([], (new CompositeWorkerActivity([]))->running());
    }
}
