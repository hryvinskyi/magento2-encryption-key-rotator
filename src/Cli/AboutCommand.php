<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Cli;

use Hryvinskyi\EncryptionKeyRotator\Application\Package\PackageVersion;
use Hryvinskyi\EncryptionKeyRotator\Application\Requirements\RuntimeRequirements;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Prints the tool version and whether the running PHP meets its requirements; fails when it does not.
 */
#[AsCommand(name: 'about', description: 'Show the tool version and check the PHP requirements')]
final class AboutCommand extends Command
{
    public function __construct(
        private readonly PackageVersion $version,
        private readonly RuntimeRequirements $requirements,
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $report = $this->requirements->check();

        $output->writeln(sprintf('Version: %s', $this->version->version()));
        $output->writeln(sprintf('PHP: %s', $report->phpVersion()));
        foreach ($report->extensions() as $extension => $loaded) {
            $output->writeln(sprintf('ext-%s: %s', $extension, $loaded ? 'loaded' : 'missing'));
        }

        if (!$report->isSatisfied()) {
            $output->writeln(sprintf(
                '<error>Missing required PHP extensions: %s</error>',
                implode(', ', array_map(static fn(string $name): string => 'ext-' . $name, $report->missingExtensions())),
            ));

            return Command::FAILURE;
        }
        $output->writeln('All requirements are met.');

        return Command::SUCCESS;
    }
}
