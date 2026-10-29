<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Infrastructure\Process;

use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Process\PsProcessTable;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectProcessFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TemporaryDirectory;
use PHPUnit\Framework\TestCase;

/**
 * The process list is read with elapsed seconds where `ps` knows `etimes`, without them where it does
 * not (a minimal `ps`), and is unavailable without a working `ps`. Each case runs a stand-in `ps` script.
 */
final class PsProcessTableTest extends TestCase
{
    private string $bin;

    protected function setUp(): void
    {
        $this->bin = TemporaryDirectory::create('key-rotator-ps');
    }

    protected function tearDown(): void
    {
        TemporaryDirectory::remove($this->bin);
    }

    public function testAPsThatKnowsElapsedSecondsGivesThem(): void
    {
        $ps = $this->script(<<<'SH'
            if [ "$1" = "-eo" ] && [ "$2" = "pid,ppid,etimes,args" ]; then
              printf '  PID  PPID ELAPSED COMMAND\n    1     0    5000 /sbin/init\n  200     1     300 php bin/magento cron:run --group=index\n'
              exit 0
            fi
            exit 1
            SH);

        self::assertSame([
            ['pid' => 1, 'ppid' => 0, 'elapsed' => 5000, 'args' => '/sbin/init'],
            ['pid' => 200, 'ppid' => 1, 'elapsed' => 300, 'args' => 'php bin/magento cron:run --group=index'],
        ], (new PsProcessTable(new DirectProcessFactory(), $ps))->processes());
    }

    public function testAPsWithoutElapsedSecondsGivesEntriesWithoutThem(): void
    {
        $ps = $this->script(<<<'SH'
            if [ "$1" = "-o" ] && [ "$2" = "pid,ppid,args" ]; then
              printf 'PID   PPID  COMMAND\n    1     0 init\n  200     1 php bin/magento cron:run\n'
              exit 0
            fi
            echo "ps: bad -o argument 'etimes'" >&2
            exit 1
            SH);

        self::assertSame([
            ['pid' => 1, 'ppid' => 0, 'elapsed' => null, 'args' => 'init'],
            ['pid' => 200, 'ppid' => 1, 'elapsed' => null, 'args' => 'php bin/magento cron:run'],
        ], (new PsProcessTable(new DirectProcessFactory(), $ps))->processes());
    }

    public function testAPsThatFailsEitherWayLeavesTheListUnavailable(): void
    {
        $ps = $this->script('exit 1');

        self::assertNull((new PsProcessTable(new DirectProcessFactory(), $ps))->processes());
    }

    public function testWithoutPsTheListIsUnavailable(): void
    {
        self::assertNull((new PsProcessTable(new DirectProcessFactory(), $this->bin . '/no-such-ps'))->processes());
    }

    private function script(string $body): string
    {
        $path = $this->bin . '/ps';
        file_put_contents($path, "#!/bin/sh\n" . $body . "\n");
        chmod($path, 0755);

        return $path;
    }
}
