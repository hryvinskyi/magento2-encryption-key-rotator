<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Cli\Output;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Cli\Output\ConsoleProgress;
use Hryvinskyi\EncryptionKeyRotator\Cli\Output\TerminalText;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * A progress message may quote what a local user chose, a process's arguments or a table's name: it is
 * printed as it is, never as styling or as terminal control.
 */
final class ConsoleProgressTest extends TestCase
{
    public function testAStepOrAWarningCannotStyleTheTerminalOrMoveItsCursor(): void
    {
        $output = new BufferedOutput(OutputInterface::VERBOSITY_NORMAL, true);
        $progress = new ConsoleProgress(new TerminalText());
        $progress->useOutput($output);

        $progress->step("php bin/magento cron:run <error>FAKE</error>\e[1A\e[2K");
        $progress->warn("worker\rDone, all good");

        $written = $output->fetch();
        self::assertStringNotContainsString("\e[1A", $written);
        self::assertStringNotContainsString("\r", $written);
        self::assertStringContainsString('cron:run <error>FAKE</error>\x1b[1A\x1b[2K', $written);
        self::assertStringContainsString('worker\x0dDone, all good', $written);
    }

    public function testAColumnNameCannotStyleTheTerminal(): void
    {
        $output = new BufferedOutput(OutputInterface::VERBOSITY_VERBOSE);
        $progress = new ConsoleProgress(new TerminalText());
        $progress->useOutput($output);

        $progress->advance(new ColumnRef("<info>x</info>\e]0;title\x07", 'value'), 3);

        self::assertSame("    <info>x</info>\\x1b]0;title\\x07.value: 3 more\n", $output->fetch());
    }
}
