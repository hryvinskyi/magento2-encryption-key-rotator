<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Cli;

use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Scan\ScanEncryptedData;
use Hryvinskyi\EncryptionKeyRotator\Cli\Option\CommandOptions;
use Hryvinskyi\EncryptionKeyRotator\Cli\Presenter\ScanPresenter;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Counts the store's encrypted values per key index, read-only.
 */
#[AsCommand(name: 'scan', description: 'Count the encrypted values per key index (read-only)')]
final class ScanCommand extends Command
{
    private const FORMAT = 'format';
    private const FORMATS = ['table', 'json'];

    public function __construct(
        private readonly ScanEncryptedData $scanner,
        private readonly ScanPresenter $presenter,
        private readonly CommandOptions $options,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->options->addStoreOptions($this);
        $this->options->addScanOptions($this);
        $this->addOption(self::FORMAT, null, InputOption::VALUE_REQUIRED, 'table or json', 'table');
        $this->setHelp(<<<'HELP'
            Reads every candidate column of the database, app/etc/env.php and app/etc/config.php, and counts the
            values per key index: verified (decrypts under that slot), retired key, unknown key, unsupported cipher,
            authentication failed. Nothing is written. No value, plaintext or ciphertext is ever printed.

            <info>--format=json</info> writes one stable JSON object on the standard output (progress goes to the
            error output):
              format_version   1
              elapsed_seconds  how long the scan took
              summary          {verified: [{index, count}], undecryptable, embedded, incomplete_columns, without_row_key: [{index, count}]}
              totals           [{index, verified, retired_key, unknown_key, unsupported_cipher,
                                 authentication_failed, unparsable}]
              columns          [{column: "table.column", row_key: [names], embedded, scan_incomplete,
                                 indices: [{index, counts: {verdict: count}}]}]
              without_row_key  [{column, shape_counts: [{index, count}], embedded, scan_incomplete}]
                               columns holding ciphertexts whose rows cannot be identified
              system_values    [{source: "env"|"committed", path: "a/b/c", key_index, verdict}]
            Counts of zero are left out of the per-column counts.
            HELP);
    }

    /**
     * @throws OptionRefused when an option cannot be used
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $format = $input->getOption(self::FORMAT);
        if (!is_string($format) || !in_array($format, self::FORMATS, true)) {
            throw new OptionRefused(sprintf('--%s is table or json.', self::FORMAT));
        }
        $report = $this->scanner->scan($this->options->scope($input), [], $this->options->batchSize($input));

        if ($format === 'json') {
            $this->presenter->json($report, $output);

            return ExitCode::DONE;
        }
        $this->presenter->text($report, $output);

        return ExitCode::DONE;
    }
}
