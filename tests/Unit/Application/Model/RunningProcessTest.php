<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\RunningProcess;
use PHPUnit\Framework\TestCase;

final class RunningProcessTest extends TestCase
{
    public function testAProcessThatStartedBeforeARingWriteMayHoldTheEarlierRing(): void
    {
        $write = new \DateTimeImmutable('2026-10-29T10:00:00+00:00');

        self::assertTrue((new RunningProcess('bin/magento cron:run', new \DateTimeImmutable('2026-10-29T09:59:59+00:00')))->startedBefore($write));
        self::assertFalse((new RunningProcess('bin/magento cron:run', $write))->startedBefore($write));
        self::assertFalse((new RunningProcess('bin/magento cron:run', new \DateTimeImmutable('2026-10-29T10:00:01+00:00')))->startedBefore($write));
    }

    public function testAProcessWhoseStartIsUnknownCountsAsOlderThanAnyRingWrite(): void
    {
        self::assertTrue((new RunningProcess('process list unavailable', null))->startedBefore(new \DateTimeImmutable('1970-01-01T00:00:00+00:00')));
    }
}
