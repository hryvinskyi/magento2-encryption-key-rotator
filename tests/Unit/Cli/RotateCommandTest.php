<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Cli;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeTransportKind;
use Hryvinskyi\EncryptionKeyRotator\Cli\ExitCode;
use Hryvinskyi\EncryptionKeyRotator\Cli\Presenter\RotatePresenter;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Cli\Support\CliWorld;
use PHPUnit\Framework\TestCase;

/**
 * `rotate` parses its options into the rotation request and the command context, refuses before any
 * write when it has no way to confirm the web tier, a key file others can read, or no confirmation, and
 * maps how the rotation ended onto its exit code.
 */
final class RotateCommandTest extends TestCase
{
    private CliWorld $cli;

    protected function setUp(): void
    {
        $this->cli = new CliWorld();
        $this->cli->world->seedDefault();
    }

    protected function tearDown(): void
    {
        $this->cli->cleanUp();
    }

    public function testWithoutAWayToConfirmTheWebTierItRefusesBeforeAnyWriteAndNamesTheThreeChoices(): void
    {
        $tester = $this->cli->run(['command' => 'rotate', '--yes' => true]);

        self::assertSame(ExitCode::REFUSED, $tester->getStatusCode());
        $error = $tester->getErrorOutput();
        self::assertStringContainsString('--probe-fcgi', $error);
        self::assertStringContainsString('--probe-url', $error);
        self::assertStringContainsString('--skip-web-probe', $error);
        $this->assertNothingWritten();
    }

    public function testTheProbeOptionsReachTheContextTheAdaptersRead(): void
    {
        $tester = $this->cli->run(['command' => 'rotate', '--yes' => true, '--probe-url' => 'http://127.0.0.1:8080', '--probe-host' => 'store.test', '--docroot' => 'web', '--probe-wait' => '7', '--insecure' => true]);

        self::assertSame(ExitCode::DONE, $tester->getStatusCode(), CliWorld::everything($tester));
        $settings = $this->cli->context->settings();
        self::assertSame(ProbeTransportKind::Http, $settings->transport());
        self::assertSame('http://127.0.0.1:8080', $settings->baseUrl());
        self::assertSame('store.test', $settings->hostHeader());
        self::assertSame('web', $settings->docroot());
        self::assertSame(7, $settings->waitSeconds());
        self::assertFalse($settings->verifyTls());
        self::assertSame($this->cli->world->root, $this->cli->context->root()->path());
        self::assertSame($this->cli->world->stateDirectory, $this->cli->context->directory());
    }

    public function testAMalformedProbeOptionIsRefusedBeforeAnyWrite(): void
    {
        $tester = $this->cli->run(['command' => 'rotate', '--yes' => true, '--probe-fcgi' => 'php-fpm.sock']);

        self::assertSame(ExitCode::REFUSED, $tester->getStatusCode());
        self::assertStringContainsString('unix:///path or tcp://host:port', $tester->getErrorOutput());
        $this->assertNothingWritten();
    }

    public function testAKeyFileItsGroupOrOthersCanReadIsRefusedAndTheKeyIsNeverPrinted(): void
    {
        $key = KeyMaterial::base64Key();
        $file = $this->cli->world->root . '/new.key';
        file_put_contents($file, $key . "\n");
        chmod($file, 0644);

        $tester = $this->cli->run(['command' => 'rotate', '--yes' => true, '--key-file' => $file] + $this->cli->probe());

        self::assertSame(ExitCode::REFUSED, $tester->getStatusCode());
        self::assertStringContainsString('chmod 600', $tester->getErrorOutput());
        self::assertStringNotContainsString($key, CliWorld::everything($tester));
        $this->assertNothingWritten();
    }

    public function testAKeyFilePrivateToItsOwnerIsTheKeyAppended(): void
    {
        $key = KeyMaterial::base64Key();
        $file = $this->cli->world->root . '/new.key';
        file_put_contents($file, $key . "\n");
        chmod($file, 0600);

        $tester = $this->cli->run(['command' => 'rotate', '--yes' => true, '--key-file' => $file] + $this->cli->probe());

        self::assertSame(ExitCode::DONE, $tester->getStatusCode(), CliWorld::everything($tester));
        self::assertSame($key, $this->cli->world->config->keyRing()->slot(3)?->raw());
        self::assertStringNotContainsString($key, CliWorld::everything($tester));
    }

    public function testWithoutInteractionAndWithoutYesItRefusesBeforeAnyWrite(): void
    {
        $tester = $this->cli->run(['command' => 'rotate'] + $this->cli->probe(), interactive: false);

        self::assertSame(ExitCode::REFUSED, $tester->getStatusCode());
        self::assertStringContainsString('--yes', $tester->getErrorOutput());
        $this->assertNothingWritten();
    }

    public function testANewRunShowsThePlanAndGoesOnOnlyWhenTheOperatorTypesYes(): void
    {
        $declined = $this->cli->run(['command' => 'rotate'] + $this->cli->probe(), ['yes']);

        self::assertSame(ExitCode::REFUSED, $declined->getStatusCode());
        self::assertStringContainsString('Plan', $declined->getDisplay());
        self::assertStringContainsString('Type YES to continue', $declined->getErrorOutput());
        self::assertStringContainsString('Not confirmed', $declined->getDisplay());
        $this->assertNothingWritten();

        $confirmed = $this->cli->run(['command' => 'rotate'] + $this->cli->probe(), ['YES']);

        self::assertSame(ExitCode::DONE, $confirmed->getStatusCode(), CliWorld::everything($confirmed));
        self::assertSame(RunState::Reencrypted, $this->cli->world->runs->active()?->state());
    }

    public function testAResumedRunIsConfirmedWithItsRunId(): void
    {
        $this->cli->world->probe->enqueue($this->cli->world->matches());
        $this->cli->world->probe->answerFromNowOn($this->cli->world->differs());
        self::assertSame(ExitCode::WAITING, $this->cli->run(['command' => 'rotate', '--yes' => true] + $this->cli->probe())->getStatusCode());
        $this->cli->world->probe->answerFromNowOn($this->cli->world->matches());
        $runId = $this->cli->lifecycle->runId()->toString();

        $declined = $this->cli->run(['command' => 'rotate'] + $this->cli->probe(), ['YES']);

        self::assertSame(ExitCode::REFUSED, $declined->getStatusCode());
        self::assertStringContainsString('Type the run id ' . $runId, $declined->getErrorOutput());
        self::assertSame(RunState::KeyAdded, $this->cli->world->runs->active()?->state());

        $confirmed = $this->cli->run(['command' => 'rotate'] + $this->cli->probe(), [$runId]);

        self::assertSame(ExitCode::DONE, $confirmed->getStatusCode(), CliWorld::everything($confirmed));
        self::assertSame(RunState::Reencrypted, $this->cli->world->runs->active()?->state());
    }

    public function testTheResultEndsWithTheRunIdWhatWasWrittenWhatRemainsTheTokenNoteAndTheNextCommands(): void
    {
        $tester = $this->cli->run(['command' => 'rotate', '--yes' => true] + $this->cli->probe());

        self::assertSame(ExitCode::DONE, $tester->getStatusCode(), CliWorld::everything($tester));
        $display = $tester->getDisplay();
        $runId = $this->cli->lifecycle->runId()->toString();
        $tail = substr($display, (int) strpos($display, 'Run: ' . $runId));
        self::assertMatchesRegularExpression('/Written: .*7 database value\(s\) and 1 app\/etc\/env\.php value\(s\)/', $tail);
        self::assertStringContainsString('Remains: 0 value(s) still under key indices 1, 2 in the database and app/etc/env.php; 1 in app/etc/config.php', $tail);
        self::assertStringContainsString(RotatePresenter::BEARER_TOKEN_NOTE, $tail);
        $root = escapeshellarg($this->cli->world->root);
        self::assertStringContainsString(sprintf('key-rotator status --magento-root=%s', $root), $tail);
        self::assertStringContainsString(sprintf("key-rotator retire --magento-root=%s --probe-fcgi='unix:///run/php-fpm.sock'", $root), $tail);
        self::assertStringContainsString(sprintf("key-rotator rollback --magento-root=%s --probe-fcgi='unix:///run/php-fpm.sock'", $root), $tail);
        self::assertStringContainsString('undoes run ' . $runId, $tail);
        foreach ($this->cli->world->plaintexts() as $plaintext) {
            self::assertStringNotContainsString($plaintext, CliWorld::everything($tester));
        }
    }

    public function testAWebTierThatDoesNotConfirmTheNewRingExitsWaiting(): void
    {
        $this->cli->world->probe->enqueue($this->cli->world->matches());
        $this->cli->world->probe->answerFromNowOn($this->cli->world->differs());

        $tester = $this->cli->run(['command' => 'rotate', '--yes' => true] + $this->cli->probe());

        self::assertSame(ExitCode::WAITING, $tester->getStatusCode());
        self::assertStringContainsString('awaiting_web_tier', $tester->getDisplay());
        self::assertStringContainsString('key-rotator rotate', $tester->getDisplay());
        self::assertSame(RunState::KeyAdded, $this->cli->world->runs->active()?->state());
    }

    public function testAPreflightRefusalExitsRefused(): void
    {
        $this->cli->world->workers->start('pid 42: php bin/magento cron:run', null);

        $tester = $this->cli->run(['command' => 'rotate', '--yes' => true] + $this->cli->probe());

        self::assertSame(ExitCode::REFUSED, $tester->getStatusCode());
        self::assertStringContainsString('[workers_running]', $tester->getDisplay());
        self::assertStringContainsString('No run was started; nothing was written.', $tester->getDisplay());
        $this->assertNothingWritten();
    }

    public function testADryRunPrintsThePlanWithoutAProbeChoiceAndWritesNothing(): void
    {
        $tester = $this->cli->run(['command' => 'rotate', '--dry-run' => true]);

        self::assertSame(ExitCode::DONE, $tester->getStatusCode(), CliWorld::everything($tester));
        self::assertStringContainsString('8 value(s) would move; 1 in app/etc/config.php stay', $tester->getDisplay());
        $this->assertNothingWritten();
    }

    public function testRotateTakesNoExclusionSoEveryColumnIsCovered(): void
    {
        $tester = $this->cli->run(['command' => 'rotate', '--yes' => true, '--skip-web-probe' => true, '--exclude' => ['oauth_consumer']]);

        self::assertNotSame(ExitCode::DONE, $tester->getStatusCode());
        self::assertFalse($this->cli->application->find('rotate')->getDefinition()->hasOption('exclude'));
        self::assertTrue($this->cli->application->find('scan')->getDefinition()->hasOption('exclude'));
        $this->assertNothingWritten();

        $rotated = $this->cli->run(['command' => 'rotate', '--yes' => true, '--skip-web-probe' => true]);

        self::assertSame(ExitCode::DONE, $rotated->getStatusCode(), CliWorld::everything($rotated));
        $newIndex = $this->cli->lifecycle->newIndex();
        foreach ([1, 2] as $id) {
            self::assertStringStartsWith($newIndex . ':3:', $this->cli->world->value('oauth_consumer', $id, 'secret'));
        }
    }

    public function testAnotherRunHoldingTheStoreRefusesWithExitCodeThreeAndNamesItsStateDirectory(): void
    {
        $this->cli->world->registry->claim(new RunId(str_repeat('f', 32)), '/srv/elsewhere/rotation');

        $tester = $this->cli->run(['command' => 'rotate', '--yes' => true] + $this->cli->probe());

        self::assertSame(ExitCode::REFUSED, $tester->getStatusCode(), CliWorld::everything($tester));
        self::assertStringContainsString('[run_claimed_elsewhere]', $tester->getDisplay());
        self::assertStringContainsString('--state-dir=/srv/elsewhere/rotation', $tester->getDisplay());
        $this->assertNothingWritten();
    }

    private function assertNothingWritten(): void
    {
        self::assertSame([], $this->cli->world->config->writes());
        self::assertNull($this->cli->world->runs->latest());
    }
}
