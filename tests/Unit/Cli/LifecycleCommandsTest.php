<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Cli;

use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackRotation;
use Hryvinskyi\EncryptionKeyRotator\Cli\ExitCode;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\Nested;
use Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Cli\Support\CliWorld;
use PHPUnit\Framework\TestCase;

/**
 * `status`, `retire`, `rollback` and `purge`: each refuses what it cannot do safely before writing, asks
 * for the run id unless `--yes`, and maps how its use case ended onto the exit code.
 */
final class LifecycleCommandsTest extends TestCase
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

    public function testStatusShowsTheRunItsStateAndTheNextCommands(): void
    {
        self::assertStringContainsString('No run', $this->cli->run(['command' => 'status'])->getDisplay());
        $this->cli->lifecycle->rotate();

        $text = $this->cli->run(['command' => 'status']);
        $json = Nested::json($this->cli->run(['command' => 'status', '--format' => 'json'])->getDisplay());

        self::assertSame(ExitCode::DONE, $text->getStatusCode());
        self::assertStringContainsString('Run: ' . $this->cli->lifecycle->runId()->toString(), $text->getDisplay());
        self::assertStringContainsString('State: reencrypted', $text->getDisplay());
        self::assertStringContainsString('key-rotator retire --magento-root=', $text->getDisplay());
        self::assertSame('reencrypted', $json['state']);
        self::assertSame(['rotate', 'retire', 'rollback'], $json['next_commands']);
        self::assertSame([1, 2], $json['source_indices']);
        self::assertSame(3, $json['new_index']);
    }

    public function testTheCommandsThatChangeTheKeyRingRefuseWithoutAWayToConfirmTheWebTier(): void
    {
        $this->cli->lifecycle->rotate();
        $writes = count($this->cli->world->config->writes());

        foreach (['retire', 'rollback'] as $command) {
            $tester = $this->cli->run(['command' => $command, '--yes' => true]);

            self::assertSame(ExitCode::REFUSED, $tester->getStatusCode(), $command);
            self::assertStringContainsString('--skip-web-probe', $tester->getErrorOutput(), $command);
        }
        self::assertCount($writes, $this->cli->world->config->writes());
        self::assertSame(RunState::Reencrypted, $this->cli->world->runs->active()?->state());
    }

    public function testRetireAsksForTheRunIdAndRetiresOnlyWhenItIsTyped(): void
    {
        $this->cli->lifecycle->rotate();
        $this->cli->lifecycle->deployCommittedUnderNewKey();
        $runId = $this->cli->lifecycle->runId()->toString();

        $declined = $this->cli->run(['command' => 'retire'] + $this->cli->probe(), ['YES']);

        self::assertSame(ExitCode::REFUSED, $declined->getStatusCode());
        self::assertStringContainsString('Type the run id ' . $runId, $declined->getErrorOutput());
        self::assertSame(RunState::Reencrypted, $this->cli->world->runs->active()?->state());

        $confirmed = $this->cli->run(['command' => 'retire'] + $this->cli->probe(), [$runId]);

        self::assertSame(ExitCode::DONE, $confirmed->getStatusCode(), CliWorld::everything($confirmed));
        self::assertStringContainsString('Retired key indices: 1, 2', $confirmed->getDisplay());
        self::assertSame(RunState::Retired, $this->cli->world->runs->active()?->state());
    }

    public function testRetireRefusedByAnInvariantExitsRefused(): void
    {
        $this->cli->lifecycle->rotate();

        $tester = $this->cli->run(['command' => 'retire', '--yes' => true] + $this->cli->probe());

        self::assertSame(ExitCode::REFUSED, $tester->getStatusCode());
        self::assertStringContainsString('[retire_blocked]', $tester->getDisplay());
    }

    public function testRetireWaitingForTheWebTierExitsWaiting(): void
    {
        $this->cli->lifecycle->rotate();
        $this->cli->lifecycle->deployCommittedUnderNewKey();
        $this->cli->world->probe->answerFromNowOn($this->cli->world->differs());

        $tester = $this->cli->run(['command' => 'retire', '--yes' => true] + $this->cli->probe());

        self::assertSame(ExitCode::WAITING, $tester->getStatusCode(), CliWorld::everything($tester));
        self::assertSame(RunState::RetirePending, $this->cli->world->runs->active()?->state());
    }

    public function testRollbackRestoresTheRingAndPrintsTheBearerTokenNote(): void
    {
        $this->cli->lifecycle->rotate();

        $tester = $this->cli->run(['command' => 'rollback', '--yes' => true] + $this->cli->probe());

        self::assertSame(ExitCode::DONE, $tester->getStatusCode(), CliWorld::everything($tester));
        self::assertStringContainsString(RollBackRotation::BEARER_TOKEN_NOTE, $tester->getDisplay());
        self::assertSame($this->cli->world->ringBefore->fingerprint(), $this->cli->world->config->keyRing()->fingerprint());
        self::assertSame(ExitCode::DONE, $this->cli->run(['command' => 'rollback', '--yes' => true] + $this->cli->probe())->getStatusCode());
    }

    public function testRollbackRefusingToRemoveAKeyTheCommittedConfigurationNeedsSaysToRedeployIt(): void
    {
        $this->cli->lifecycle->rotate();
        $this->cli->lifecycle->deployCommittedUnderNewKey();

        $tester = $this->cli->run(['command' => 'rollback', '--yes' => true] + $this->cli->probe());

        self::assertSame(ExitCode::REFUSED, $tester->getStatusCode(), CliWorld::everything($tester));
        self::assertStringContainsString('[committed_values_on_removed_key]', $tester->getDisplay());
        self::assertStringContainsString('Redeploy app/etc/config.php', $tester->getDisplay());
        self::assertStringContainsString('key-rotator rollback', $tester->getDisplay());
    }

    public function testAConflictLeftAloneByTheRollbackNamesItsColumnAsVisibleText(): void
    {
        $life = $this->cli->lifecycle;
        $world = $this->cli->world;
        $world->database->createTable("evil\e[2J", ['entity_id'], ['secret']);
        $world->seed("evil\e[2J", 1, 'secret', 'hidden', 2);
        $life->rotate();
        $world->database->update("evil\e[2J", ['entity_id' => 1], 'secret', 'set in plain text');

        $tester = $this->cli->run(['command' => 'rollback', '--yes' => true] + $this->cli->probe());

        self::assertSame(ExitCode::DONE, $tester->getStatusCode(), CliWorld::everything($tester));
        self::assertStringNotContainsString("\e", $tester->getDisplay());
        self::assertStringContainsString('evil\x1b[2J.secret row', $tester->getDisplay());
    }

    public function testRollbackRemovesTheNewKeyDespiteEmbeddedValuesOnlyWhenTheyAreAcknowledged(): void
    {
        $life = $this->cli->lifecycle;
        $world = $this->cli->world;
        $life->rotate();
        $world->database->createTable('sales_payment', ['entity_id'], ['additional_information']);
        $world->database->insert('sales_payment', [
            'entity_id' => 1,
            'additional_information' => json_encode(['token' => $world->encrypt('embedded secret', $life->newIndex(), $life->newKey())], JSON_THROW_ON_ERROR),
        ]);

        $refused = $this->cli->run(['command' => 'rollback', '--yes' => true] + $this->cli->probe());

        self::assertSame(ExitCode::REFUSED, $refused->getStatusCode(), CliWorld::everything($refused));
        self::assertStringContainsString('[rollback_blocked]', $refused->getDisplay());

        $accepted = $this->cli->run(['command' => 'rollback', '--yes' => true, '--accept-embedded' => true] + $this->cli->probe());

        self::assertSame(ExitCode::DONE, $accepted->getStatusCode(), CliWorld::everything($accepted));
        self::assertSame($world->ringBefore->fingerprint(), $world->config->keyRing()->fingerprint());
    }

    public function testRollbackAsksForTheRunId(): void
    {
        $this->cli->lifecycle->rotate();

        $declined = $this->cli->run(['command' => 'rollback'] + $this->cli->probe(), ['no']);

        self::assertSame(ExitCode::REFUSED, $declined->getStatusCode());
        self::assertSame(RunState::Reencrypted, $this->cli->world->runs->active()?->state());
        self::assertSame(
            ExitCode::DONE,
            $this->cli->run(['command' => 'rollback'] + $this->cli->probe(), [$this->cli->lifecycle->runId()->toString()])->getStatusCode(),
        );
    }

    public function testPurgeAsksForTheRunIdThenDestroysWhatTheRunKept(): void
    {
        $this->cli->lifecycle->rotate();
        $this->cli->lifecycle->deployCommittedUnderNewKey();
        $this->cli->lifecycle->retireRotated();
        $runId = $this->cli->lifecycle->runId()->toString();

        $declined = $this->cli->run(['command' => 'purge'], ['no']);
        self::assertSame(ExitCode::REFUSED, $declined->getStatusCode());
        self::assertStringContainsString('Type the run id ' . $runId, $declined->getErrorOutput());

        $purged = $this->cli->run(['command' => 'purge'], [$runId]);

        self::assertSame(ExitCode::DONE, $purged->getStatusCode(), CliWorld::everything($purged));
        self::assertStringContainsString('Purge: purged', $purged->getDisplay());
        self::assertNull($this->cli->world->runs->latest());
        self::assertSame(ExitCode::DONE, $this->cli->run(['command' => 'purge', '--yes' => true])->getStatusCode());
    }

    public function testPurgeOfAnUnfinishedRunOrAMalformedRunIdIsRefused(): void
    {
        $this->cli->lifecycle->rotate();

        self::assertSame(ExitCode::REFUSED, $this->cli->run(['command' => 'purge', '--yes' => true])->getStatusCode());
        self::assertSame(ExitCode::REFUSED, $this->cli->run(['command' => 'purge', '--yes' => true, '--run-id' => 'not-a-run'])->getStatusCode());
        self::assertSame(RunState::Reencrypted, $this->cli->world->runs->active()?->state());
    }
}
