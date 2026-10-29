<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Cli;

use Hryvinskyi\EncryptionKeyRotator\Cli\ExitCode;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\Nested;
use Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Cli\Support\CliWorld;
use PHPUnit\Framework\TestCase;

/**
 * `scan` reports counts only, as text or as the stable JSON object its help documents, and never a value.
 */
final class ScanCommandTest extends TestCase
{
    private CliWorld $cli;

    /**
     * @var list<string> the stored values the world seeded
     */
    private array $stored = [];

    protected function setUp(): void
    {
        $this->cli = new CliWorld();
        $this->cli->world->database->createTable('core_config_data', ['config_id'], ['value']);
        foreach ([1 => 1, 2 => 1, 3 => 2] as $id => $index) {
            $this->stored[] = $this->cli->world->seed('core_config_data', $id, 'value', sprintf('scan secret %d', $id), $index, 'config_id');
        }
    }

    protected function tearDown(): void
    {
        $this->cli->cleanUp();
    }

    public function testTheJsonReportHasTheDocumentedShape(): void
    {
        $tester = $this->cli->run(['command' => 'scan', '--format' => 'json']);

        self::assertSame(ExitCode::DONE, $tester->getStatusCode(), CliWorld::everything($tester));
        $report = Nested::json($tester->getDisplay());
        self::assertSame(['format_version', 'elapsed_seconds', 'summary', 'totals', 'columns', 'without_row_key', 'system_values'], array_keys($report));
        self::assertSame(1, $report['format_version']);
        self::assertSame(['verified', 'undecryptable', 'embedded', 'incomplete_columns', 'without_row_key'], array_keys(Nested::array($report, 'summary')));
        self::assertSame([['index' => 1, 'count' => 3], ['index' => 2, 'count' => 2]], Nested::value($report, 'summary', 'verified'));
        self::assertSame(
            ['index' => 1, 'verified' => 3, 'retired_key' => 0, 'unknown_key' => 0, 'unsupported_cipher' => 0, 'authentication_failed' => 0, 'unparsable' => 0],
            Nested::value($report, 'totals', 0),
        );
        self::assertSame([
            'column' => 'core_config_data.value',
            'row_key' => ['config_id'],
            'embedded' => 0,
            'scan_incomplete' => false,
            'indices' => [['index' => 1, 'counts' => ['verified' => 2]], ['index' => 2, 'counts' => ['verified' => 1]]],
        ], Nested::value($report, 'columns', 0));
        self::assertSame([], $report['without_row_key']);
        self::assertSame([
            ['source' => 'env', 'path' => 'payment/gateway/api_secret', 'key_index' => 2, 'verdict' => 'verified'],
            ['source' => 'committed', 'path' => 'carriers/courier/password', 'key_index' => 1, 'verdict' => 'verified'],
        ], $report['system_values']);
    }

    public function testNeitherFormatPrintsAValueOrAPlaintext(): void
    {
        foreach (['json', 'table'] as $format) {
            $everything = CliWorld::everything($this->cli->run(['command' => 'scan', '--format' => $format]));

            foreach ([...$this->stored, ...$this->cli->world->plaintexts()] as $secret) {
                self::assertStringNotContainsString($secret, $everything, $format);
            }
        }
    }

    public function testTheTableShowsTheCountsPerKeyIndex(): void
    {
        $tester = $this->cli->run(['command' => 'scan']);

        self::assertSame(ExitCode::DONE, $tester->getStatusCode());
        self::assertStringContainsString('key index 1: 3 verified', $tester->getDisplay());
        self::assertStringContainsString('key index 2: 2 verified', $tester->getDisplay());
    }

    public function testAColumnNameHoldingControlCharactersOrATagIsPrintedAsVisibleText(): void
    {
        $world = $this->cli->world;
        $world->database->createTable("evil\e[2J<info>", ['entity_id'], ['secret']);
        $world->seed("evil\e[2J<info>", 1, 'secret', 'hidden', 2);

        $tester = $this->cli->run(['command' => 'scan', '-v' => true]);

        self::assertSame(ExitCode::DONE, $tester->getStatusCode(), CliWorld::everything($tester));
        self::assertStringNotContainsString("\e", $tester->getDisplay());
        self::assertStringContainsString('evil\x1b[2J<info>.secret', $tester->getDisplay());
    }

    public function testAnUnknownFormatOrAMalformedExclusionIsRefused(): void
    {
        self::assertSame(ExitCode::REFUSED, $this->cli->run(['command' => 'scan', '--format' => 'xml'])->getStatusCode());
        self::assertSame(ExitCode::REFUSED, $this->cli->run(['command' => 'scan', '--exclude' => ['core config']])->getStatusCode());
        self::assertSame(ExitCode::REFUSED, $this->cli->run(['command' => 'scan', '--batch-size' => '0'])->getStatusCode());
    }

    public function testAnExcludedColumnIsLeftOut(): void
    {
        $tester = $this->cli->run(['command' => 'scan', '--format' => 'json', '--exclude' => ['core_config_data']]);

        self::assertSame([], Nested::value(Nested::json($tester->getDisplay()), 'columns'));
    }
}
