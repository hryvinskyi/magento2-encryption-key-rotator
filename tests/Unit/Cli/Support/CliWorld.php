<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Cli\Support;

use Hryvinskyi\EncryptionKeyRotator\Application\Package\PackageVersion;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\SecretRedactor;
use Hryvinskyi\EncryptionKeyRotator\Cli\Confirmation\Confirmation;
use Hryvinskyi\EncryptionKeyRotator\Cli\ConsoleApplication;
use Hryvinskyi\EncryptionKeyRotator\Cli\Context\CommandContext;
use Hryvinskyi\EncryptionKeyRotator\Cli\Context\CommandContextListener;
use Hryvinskyi\EncryptionKeyRotator\Cli\Option\CommandOptions;
use Hryvinskyi\EncryptionKeyRotator\Cli\Output\ConsoleProgress;
use Hryvinskyi\EncryptionKeyRotator\Cli\Output\TerminalText;
use Hryvinskyi\EncryptionKeyRotator\Cli\Presenter\PurgePresenter;
use Hryvinskyi\EncryptionKeyRotator\Cli\Presenter\ReportSections;
use Hryvinskyi\EncryptionKeyRotator\Cli\Presenter\RetirePresenter;
use Hryvinskyi\EncryptionKeyRotator\Cli\Presenter\RollBackPresenter;
use Hryvinskyi\EncryptionKeyRotator\Cli\Presenter\RotatePresenter;
use Hryvinskyi\EncryptionKeyRotator\Cli\Presenter\ScanPresenter;
use Hryvinskyi\EncryptionKeyRotator\Cli\Presenter\StatusPresenter;
use Hryvinskyi\EncryptionKeyRotator\Cli\PurgeCommand;
use Hryvinskyi\EncryptionKeyRotator\Cli\RetireCommand;
use Hryvinskyi\EncryptionKeyRotator\Cli\RollbackCommand;
use Hryvinskyi\EncryptionKeyRotator\Cli\Rotate\KeyFile;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\FixedRuntimeUser;
use Hryvinskyi\EncryptionKeyRotator\Cli\RotateCommand;
use Hryvinskyi\EncryptionKeyRotator\Cli\ScanCommand;
use Hryvinskyi\EncryptionKeyRotator\Cli\StatusCommand;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectMagentoRootFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectProbeSettingsFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectPurgeRequestFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectQuestionFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectRetireRequestFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectRollBackRequestFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectRotateRequestFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectRunIdFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectScanScopeFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\PassThroughSecretRedactor;
use Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase\Support\LifecycleWorld;
use Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase\Support\RotationWorld;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\QuestionHelper;
use Symfony\Component\Console\Tester\ApplicationTester;
use Symfony\Component\EventDispatcher\EventDispatcher;

/**
 * The console application as the container builds it — every command, the context listener on the
 * dispatcher, the presenters and the confirmation — over the use cases of a {@see LifecycleWorld}, whose
 * ports are in-memory doubles. A test runs a command line through {@see run()} and reads what the
 * operator would see.
 */
final class CliWorld
{
    public readonly LifecycleWorld $lifecycle;
    public readonly RotationWorld $world;
    public readonly CommandContext $context;
    public readonly ConsoleProgress $progress;
    public readonly ConsoleApplication $application;

    /**
     * @param list<Command> $extraCommands commands a test adds beside the tool's own
     */
    public function __construct(array $extraCommands = [], ?SecretRedactor $redactor = null, bool $usableFirstSlot = false)
    {
        $this->lifecycle = new LifecycleWorld($usableFirstSlot);
        $this->world = $this->lifecycle->world;
        $this->context = new CommandContext();
        $this->progress = new ConsoleProgress(new TerminalText());

        $options = new CommandOptions(new DirectMagentoRootFactory(), new DirectProbeSettingsFactory(), new DirectScanScopeFactory());
        $confirmation = new Confirmation(new QuestionHelper(), new DirectQuestionFactory(), $options);
        $sections = new ReportSections(new TerminalText());
        $statusPresenter = new StatusPresenter($sections);

        $dispatcher = new EventDispatcher();
        $dispatcher->addSubscriber(new CommandContextListener($this->context, $this->progress, $options));

        $commands = [
            new ScanCommand($this->world->scanner, new ScanPresenter($sections), $options),
            new StatusCommand($this->world->status, $statusPresenter, $options),
            new RotateCommand(
                $this->world->rotateKey,
                $this->world->status,
                new DirectRotateRequestFactory(),
                $this->context,
                new KeyFile(new FixedRuntimeUser((int) fileowner($this->world->root))),
                $confirmation,
                new RotatePresenter($sections),
                $statusPresenter,
                $options,
            ),
            new RetireCommand(
                $this->lifecycle->retireOldKeys,
                $this->world->status,
                new DirectRetireRequestFactory(),
                $this->context,
                $confirmation,
                new RetirePresenter($sections),
                $statusPresenter,
                $options,
            ),
            new RollbackCommand(
                $this->lifecycle->rollBackRotation,
                $this->world->status,
                new DirectRollBackRequestFactory(),
                $this->context,
                $confirmation,
                new RollBackPresenter($sections),
                $statusPresenter,
                $options,
            ),
            new PurgeCommand(
                $this->lifecycle->purgeRotation,
                $this->world->status,
                new DirectPurgeRequestFactory(),
                new DirectRunIdFactory(),
                $confirmation,
                new PurgePresenter($sections),
                $statusPresenter,
                $options,
            ),
            ...$extraCommands,
        ];

        $version = new class implements PackageVersion {
            public function version(): string
            {
                return '1.2.3';
            }
        };
        $this->application = new ConsoleApplication($commands, $dispatcher, $version, $redactor ?? new PassThroughSecretRedactor(), new TerminalText());
        $this->application->setAutoExit(false);
    }

    /**
     * Runs a command line against the world's store; the Magento root is the world's unless given.
     *
     * @param array<string, mixed> $input   the command name under `command`, options as `--name`
     * @param list<string>         $answers what the operator types at the prompts; given answers make the run interactive
     */
    public function run(array $input, array $answers = [], ?bool $interactive = null): ApplicationTester
    {
        $tester = new ApplicationTester($this->application);
        $tester->setInputs($answers);
        $name = $input['command'] ?? null;
        if (is_string($name) && $this->application->find($name)->getDefinition()->hasOption('magento-root')) {
            $input += ['--magento-root' => $this->world->root];
        }
        $tester->run(
            $input,
            ['interactive' => $interactive ?? $answers !== [], 'capture_stderr_separately' => true],
        );

        return $tester;
    }

    /**
     * The probe options of a FastCGI probe, which the world's scripted web tier answers.
     *
     * @return array<string, mixed>
     */
    public function probe(): array
    {
        return ['--probe-fcgi' => 'unix:///run/php-fpm.sock', '--probe-wait' => '5'];
    }

    /**
     * Everything the operator saw: the standard and the error output.
     */
    public static function everything(ApplicationTester $tester): string
    {
        return $tester->getDisplay() . "\n" . $tester->getErrorOutput();
    }

    public function cleanUp(): void
    {
        $this->lifecycle->cleanUp();
    }
}
