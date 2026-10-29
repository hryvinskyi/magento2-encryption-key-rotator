<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Cli\Presenter;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\CacheCleanOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Conflict;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ConflictReason;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeStatus;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RowKey;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RunningProcess;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Reencryption\ReencryptionOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\Refusal;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\RefusalReason;
use Hryvinskyi\EncryptionKeyRotator\Cli\Output\TerminalText;
use Hryvinskyi\EncryptionKeyRotator\Cli\Presenter\ReportSections;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * The sections print process arguments, database identifiers and messages as text: nothing in them
 * reaches the terminal as a style tag or a control character.
 */
final class ReportSectionsTest extends TestCase
{
    private const HOSTILE = "<error>x</error>\e[2K\r\u{9B}0m";
    private const SHOWN = '<error>x</error>\x1b[2K\x0d\x9b0m';

    private BufferedOutput $output;

    private ReportSections $sections;

    protected function setUp(): void
    {
        $this->output = new BufferedOutput(BufferedOutput::VERBOSITY_NORMAL, true);
        $this->sections = new ReportSections(new TerminalText());
    }

    public function testAProcessArgumentListIsPrintedAsText(): void
    {
        $this->sections->workers($this->output, [new RunningProcess('php bin/magento queue:consumers:start ' . self::HOSTILE, null)]);

        $this->assertPrintedAsText();
    }

    public function testRefusalProbeAndCacheMessagesArePrintedAsText(): void
    {
        $this->sections->refusals($this->output, [new Refusal(RefusalReason::WorkersRunning, self::HOSTILE)]);
        $this->sections->probe($this->output, new ProbeOutcome(ProbeStatus::Unreachable, self::HOSTILE));
        $this->sections->cacheClean($this->output, new CacheCleanOutcome(false, self::HOSTILE));
        $this->sections->nextCommands($this->output, ['key-rotator status ' . self::HOSTILE]);
        $this->sections->systemPaths($this->output, ['payment/' . self::HOSTILE]);

        $this->assertPrintedAsText();
    }

    public function testTableAndColumnNamesOfAReencryptionArePrintedAsText(): void
    {
        $column = new ColumnRef('t' . "\e[2K", 'v' . "\r");
        $this->sections->reencryption($this->output, 'Database', new ReencryptionOutcome(
            [$column->toString() => 2],
            [new Conflict($column, new RowKey(['id' => self::HOSTILE]), ConflictReason::Changed)],
            [$column->toString() => ['undecryptable' => 1]],
            1,
        ));

        $written = $this->output->fetch();
        self::assertStringNotContainsString("\e[2K", $written);
        self::assertStringNotContainsString("\r", $written);
        self::assertStringContainsString('t\x1b[2K.v\x0d: 2 rewritten', $written);
        self::assertStringContainsString('t\x1b[2K.v\x0d: left alone: 1 undecryptable', $written);
        self::assertStringContainsString('t\x1b[2K.v\x0d row ', $written);
    }

    private function assertPrintedAsText(): void
    {
        $written = $this->output->fetch();
        self::assertStringNotContainsString("\e[2K", $written);
        self::assertStringNotContainsString("\r", $written);
        self::assertStringNotContainsString("\u{9B}", $written);
        self::assertStringContainsString(self::SHOWN, $written);
    }
}
