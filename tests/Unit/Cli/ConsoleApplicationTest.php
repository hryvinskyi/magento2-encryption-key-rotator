<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Cli;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\ConflictingRuns;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunLocked;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\UnusableStateDirectory;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run\UntrustedStateDirectory;
use Hryvinskyi\EncryptionKeyRotator\Cli\ExitCode;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Security\PatternSecretRedactor;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectCiphertextFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectDatabaseSettingsFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\InMemoryDeploymentConfig;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Cli\Support\CliWorld;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Whatever a command throws ends as one redacted line on the error output: a refusal (exit 3) when it is
 * one, an unexpected error (exit 1) otherwise, whatever code the exception carries; the trace only with
 * `-vvv`.
 */
final class ConsoleApplicationTest extends TestCase
{
    private const PASSWORD = 'db-password-Xq7vL2';

    private ?\Throwable $throw = null;

    private CliWorld $cli;

    private string $ciphertext;

    private string $rawKey;

    protected function setUp(): void
    {
        $failing = new class ($this->throw(...)) extends Command {
            /**
             * @param \Closure(): \Throwable $throwable
             */
            public function __construct(private readonly \Closure $throwable)
            {
                parent::__construct('fail');
            }

            protected function execute(InputInterface $input, OutputInterface $output): int
            {
                throw ($this->throwable)();
            }
        };
        $settings = (new DirectDatabaseSettingsFactory())->create('db', 3306, null, 'store', 'store', self::PASSWORD, '', '');
        $config = new InMemoryDeploymentConfig(
            (new CliWorld())->world->ringParser->parse(KeyMaterial::base64Key()),
            databaseSettings: $settings,
        );
        $this->cli = new CliWorld([$failing], new PatternSecretRedactor($config));
        $this->ciphertext = (new DirectCiphertextFactory())->create(1, 3, base64_encode(random_bytes(48)))->toString();
        $this->rawKey = KeyMaterial::base64Key();
    }

    protected function tearDown(): void
    {
        $this->cli->cleanUp();
    }

    public function testAnUnexpectedErrorIsOneRedactedLineAndExitsOneWhateverItsCode(): void
    {
        $this->throw = new \RuntimeException(sprintf('Write of %s with key %s failed for password %s', $this->ciphertext, $this->rawKey, self::PASSWORD), ExitCode::REFUSED);

        $tester = $this->cli->run(['command' => 'fail']);

        self::assertSame(ExitCode::UNEXPECTED, $tester->getStatusCode());
        $error = trim($tester->getErrorOutput());
        self::assertSame(1, substr_count($error, "\n") + 1, $error);
        self::assertStringStartsWith('Error: Write of [redacted] with key [redacted] failed for password [redacted]', $error);
        self::assertSame('', $tester->getDisplay());
    }

    public function testTheTraceIsShownOnlyWithDebugVerbosityAndStaysRedacted(): void
    {
        $this->throw = new \LogicException('Broken with ' . $this->rawKey);

        $quiet = $this->cli->run(['command' => 'fail', '-vv' => true]);
        $debug = $this->cli->run(['command' => 'fail', '-vvv' => true]);

        self::assertStringNotContainsString('#0 ', $quiet->getErrorOutput());
        self::assertStringContainsString('LogicException thrown in', $debug->getErrorOutput());
        self::assertStringContainsString('#0 ', $debug->getErrorOutput());
        self::assertStringNotContainsString($this->rawKey, $debug->getErrorOutput());
    }

    /**
     * @return iterable<string, array{\Throwable}>
     */
    public static function refusals(): iterable
    {
        yield 'another process holds the lock' => [new RunLocked('Another process holds the lock of the state directory.')];
        yield 'more than one unfinished run' => [new ConflictingRuns('The state directory holds two unfinished runs.')];
        yield 'a state directory that cannot be used' => [new UnusableStateDirectory('The state directory /srv/rotation is writable by its group; pass a safe --state-dir.')];
        yield 'a state directory the run store does not trust' => [new UntrustedStateDirectory('/srv/rotation/run is a symbolic link; pass a safe --state-dir.')];
    }

    #[DataProvider('refusals')]
    public function testARunStoreThatCannotBeUsedSafelyIsARefusal(\Throwable $refusal): void
    {
        $this->throw = $refusal;

        $tester = $this->cli->run(['command' => 'fail']);

        self::assertSame(ExitCode::REFUSED, $tester->getStatusCode());
        self::assertStringStartsWith('Refused: ' . $refusal->getMessage(), trim($tester->getErrorOutput()));
    }

    public function testAMessageQuotingControlCharactersOrStyleTagsReachesTheTerminalAsVisibleText(): void
    {
        $this->throw = new RunLocked("Held by php \e[2J\rbin/magento <error>cron:run</error>\x9b");

        $tester = $this->cli->run(['command' => 'fail']);

        self::assertSame(ExitCode::REFUSED, $tester->getStatusCode());
        $error = trim($tester->getErrorOutput());
        self::assertStringNotContainsString("\e", $error);
        self::assertStringNotContainsString("\r", $error);
        self::assertStringContainsString('\x1b[2J\x0dbin/magento <error>cron:run</error>', $error, 'The quoted tag is printed, not applied.');
    }

    private function throw(): \Throwable
    {
        return $this->throw ?? new \LogicException('The test set nothing to throw.');
    }
}
