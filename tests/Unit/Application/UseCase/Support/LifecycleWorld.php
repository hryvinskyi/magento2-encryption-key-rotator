<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase\Support;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\KeptKeyRole;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueSource;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge\PurgeRequest;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge\PurgeResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge\PurgeRotation;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Reencryption\SystemValueReencryption;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\PlaceholderRingWriter;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\RetireOldKeys;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\RetireRequest;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\RetireResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\RetireStatus;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\ForwardJournalReversal;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackRequest;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackRotation;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollbackRingWriter;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate\RotateStatus;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Scan\VerifiedValuesOnIndices;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\Key;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRun;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Crypto\RandomKeyGenerator;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectJournalReversalOutcomeFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeyFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeyRingFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeySlotFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectPurgeResultFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectReencryptionFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectRefusalFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectRetireResultFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectRollBackResultFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectScanScopeFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectSystemValueChangeFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\SequentialRunIdGenerator;

/**
 * A store for the tests of what follows a rotation: a {@see RotationWorld} (its doubles, the real cipher
 * and the rotation itself) with the retirement, the rollback and the purge wired onto the same doubles, as
 * the container wires them.
 *
 * The world's run is the first one its run id generator issues. Its default committed configuration holds
 * a value under an old key, which the tool never rewrites: {@see deployCommittedUnderNewKey()} plays the
 * deploy that ships it re-encrypted, as an operator does before retiring.
 */
final class LifecycleWorld
{
    public readonly RotationWorld $world;
    public readonly RetireOldKeys $retireOldKeys;
    public readonly RollBackRotation $rollBackRotation;
    public readonly PurgeRotation $purgeRotation;

    public function __construct(bool $usableFirstSlot = false)
    {
        $world = new RotationWorld(usableFirstSlot: $usableFirstSlot);
        $this->world = $world;
        $keys = new DirectKeyFactory();
        $slots = new DirectKeySlotFactory();
        $rings = new DirectKeyRingFactory();
        $refusals = new DirectRefusalFactory();
        $scopes = new DirectScanScopeFactory();
        $systemValues = new SystemValueReencryption($world->config, $world->config, $world->cipher, new DirectSystemValueChangeFactory());
        $verified = new VerifiedValuesOnIndices();

        $this->retireOldKeys = new RetireOldKeys(
            $world->runs,
            $world->config,
            $world->preflight,
            $world->storeClaim,
            new PlaceholderRingWriter(
                $world->runs,
                $world->config,
                $world->config,
                new RandomKeyGenerator($keys),
                $slots,
                $rings,
                $world->verifier,
                $refusals,
                $world->progress,
                $world->clock,
            ),
            $world->webTier,
            $world->scanner,
            $world->columnReencryption,
            $systemValues,
            $world->cache,
            $verified,
            $keys,
            $scopes,
            new DirectRetireResultFactory(),
            $refusals,
            $world->progress,
            $world->clock,
        );
        $this->rollBackRotation = new RollBackRotation(
            $world->runs,
            $world->config,
            $world->preflight,
            $world->storeClaim,
            new RollbackRingWriter($world->runs, $world->config, $world->config, $slots, $rings, $refusals, $world->progress, $world->clock),
            $world->webTier,
            new ForwardJournalReversal(
                $world->database,
                $world->database,
                $world->ciphertextParser,
                $world->cipher,
                new DirectReencryptionFactory(),
                new DirectJournalReversalOutcomeFactory(),
                $world->progress,
            ),
            $world->columnReencryption,
            $systemValues,
            $world->cache,
            $world->scanner,
            $verified,
            $keys,
            $scopes,
            new DirectRollBackResultFactory(),
            $refusals,
            $world->progress,
            $world->clock,
        );
        $this->purgeRotation = new PurgeRotation(
            $world->runs,
            $world->scanner,
            $verified,
            $world->database,
            $world->storeClaim,
            $keys,
            $scopes,
            new DirectPurgeResultFactory(),
            $refusals,
            $world->progress,
            $world->clock,
        );
    }

    /**
     * The id of the world's run.
     */
    public function runId(): RunId
    {
        return SequentialRunIdGenerator::id(1);
    }

    /**
     * The world's run as the store holds it now.
     */
    public function run(): RotationRun
    {
        return $this->world->runs->get($this->runId());
    }

    /**
     * Rotates the key, failing the test setup when the rotation does not reach `reencrypted`.
     */
    public function rotate(): void
    {
        $result = $this->world->rotate();
        if ($result->status() !== RotateStatus::Reencrypted) {
            throw new \LogicException(sprintf('The rotation ended "%s".', $result->status()->value));
        }
    }

    /**
     * The key the run appended, as the run keeps it.
     */
    public function newKey(): Key
    {
        foreach ($this->world->runs->keptKeys($this->runId(), KeptKeyRole::Added) as $slot) {
            return $slot->key(new DirectKeyFactory()) ?? throw new \LogicException('The kept new key is a placeholder.');
        }

        throw new \LogicException('The run keeps no new key.');
    }

    /**
     * The index the run appended its key at.
     */
    public function newIndex(): int
    {
        return $this->run()->newIndex() ?? throw new \LogicException('The run announced no new key.');
    }

    /**
     * Plays the deploy of a committed configuration whose value was re-encrypted under the new key in the
     * repository.
     */
    public function deployCommittedUnderNewKey(): void
    {
        $this->world->config->deployCommittedSystemValues([new SystemValue(
            RotationWorld::COMMITTED_PATH,
            $this->world->ciphertext('committed secret', $this->newIndex(), $this->newKey()),
            SystemValueSource::Committed,
        )]);
    }

    /**
     * Plays the deploy, before a rollback, of a committed configuration whose value is encrypted again under
     * the key that was active before the run.
     */
    public function deployCommittedUnderOldKey(): void
    {
        $this->world->config->deployCommittedSystemValues([new SystemValue(
            RotationWorld::COMMITTED_PATH,
            $this->world->ciphertext('committed secret', $this->run()->activeIndexBefore()),
            SystemValueSource::Committed,
        )]);
    }

    /**
     * Rotates, deploys the committed configuration under the new key and retires the old keys, failing the
     * test setup when the retirement does not end `retired`.
     */
    public function rotateAndRetire(): void
    {
        $this->rotate();
        $this->retireRotated();
    }

    /**
     * Deploys the committed configuration under the new key and retires the old keys of a rotated run,
     * failing the test setup when the retirement does not end `retired`.
     */
    public function retireRotated(): void
    {
        $this->deployCommittedUnderNewKey();
        $result = $this->retire();
        if ($result->status() !== RetireStatus::Retired) {
            throw new \LogicException(sprintf('The retirement ended "%s".', $result->status()->value));
        }
    }

    public function retireRequest(
        bool $acceptEmbedded = false,
        bool $cacheCleanedManually = false,
        bool $ignoreWorkers = false,
        bool $allowOtherUser = false,
        ?ProbeSettings $probeSettings = null,
    ): RetireRequest {
        return new RetireRequest($acceptEmbedded, $cacheCleanedManually, $ignoreWorkers, $allowOtherUser, $probeSettings ?? $this->world->probeSettings());
    }

    public function retire(?RetireRequest $request = null): RetireResult
    {
        return $this->retireOldKeys->retire($request ?? $this->retireRequest());
    }

    public function rollBackRequest(bool $ignoreWorkers = false, bool $allowOtherUser = false, ?ProbeSettings $probeSettings = null, bool $acceptEmbedded = false): RollBackRequest
    {
        return new RollBackRequest($ignoreWorkers, $allowOtherUser, $probeSettings ?? $this->world->probeSettings(), $acceptEmbedded);
    }

    public function rollBack(?RollBackRequest $request = null): RollBackResult
    {
        return $this->rollBackRotation->rollBack($request ?? $this->rollBackRequest());
    }

    public function purge(?RunId $runId = null, bool $acceptLoss = false): PurgeResult
    {
        return $this->purgeRotation->purge(new PurgeRequest($runId, $acceptLoss));
    }

    public function cleanUp(): void
    {
        $this->world->cleanUp();
    }
}
