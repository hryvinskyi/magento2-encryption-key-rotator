<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Cli;

use Hryvinskyi\EncryptionKeyRotator\Application\Package\PackageVersion;
use Hryvinskyi\EncryptionKeyRotator\Application\Requirements\RequirementsReport;
use Hryvinskyi\EncryptionKeyRotator\Application\Requirements\RuntimeRequirements;
use Hryvinskyi\EncryptionKeyRotator\Cli\AboutCommand;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

final class AboutCommandTest extends TestCase
{
    public function testAllRequirementsPresentSucceedsAndPrintsTheVersions(): void
    {
        $tester = $this->tester(['sodium' => true, 'pdo_mysql' => true, 'json' => true]);

        $exitCode = $tester->execute([]);

        self::assertSame(Command::SUCCESS, $exitCode);
        $display = $tester->getDisplay();
        self::assertStringContainsString('Version: 2.0.1', $display);
        self::assertStringContainsString('PHP: 8.1.30', $display);
        self::assertStringContainsString('ext-sodium: loaded', $display);
        self::assertStringContainsString('ext-pdo_mysql: loaded', $display);
        self::assertStringContainsString('ext-json: loaded', $display);
        self::assertStringNotContainsString('Missing', $display);
    }

    public function testMissingExtensionFailsAndNamesIt(): void
    {
        $tester = $this->tester(['sodium' => true, 'pdo_mysql' => false, 'json' => true]);

        $exitCode = $tester->execute([]);

        self::assertSame(Command::FAILURE, $exitCode);
        $display = $tester->getDisplay();
        self::assertStringContainsString('ext-pdo_mysql: missing', $display);
        self::assertStringContainsString('Missing required PHP extensions: ext-pdo_mysql', $display);
        self::assertStringNotContainsString('ext-sodium,', $display);
    }

    /**
     * @param array<string, bool> $extensions
     */
    private function tester(array $extensions): CommandTester
    {
        $version = new class implements PackageVersion {
            public function version(): string
            {
                return '2.0.1';
            }
        };
        $requirements = new class ($extensions) implements RuntimeRequirements {
            /**
             * @param array<string, bool> $extensions
             */
            public function __construct(private readonly array $extensions) {}

            public function check(): RequirementsReport
            {
                return new RequirementsReport('8.1.30', $this->extensions);
            }
        };

        return new CommandTester(new AboutCommand($version, $requirements));
    }
}
