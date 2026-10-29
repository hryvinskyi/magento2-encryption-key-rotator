<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Run;

use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Ciphertext;

/**
 * One rotation of a store's encryption key, from the moment it starts until its kept material is
 * purged: the aggregate root every rotation step records itself in.
 *
 * The run knows the ring as it was before the run (by fingerprint only, never by key), the old indices
 * whose values it moves, the index of the key it appends, and the ring it last wrote. Every key ring
 * write is announced first: the run records the fingerprint of the ring about to be written, and accepts
 * the write as done only when the ring found afterwards has exactly that fingerprint. A crash between the
 * write and the next save can therefore always be told apart from a write made by someone else.
 *
 * Every state change is checked against {@see RunState}; one the current state does not allow throws
 * {@see IllegalRunTransition} and changes nothing. Retiring the old keys is refused while the last
 * recorded scan still finds values on them (values that decrypt there, and whole ciphertexts on them in
 * columns without a row key, which no acknowledgement of embedded values waives), while embedded values
 * or incompletely scanned columns are unacknowledged, or while the configuration cache was not cleaned
 * after the last re-encryption, each unless its override is given; given overrides are recorded.
 *
 * The run holds no secret: its {@see snapshot()} can be written to disk as it is. Created through
 * {@see RotationRunFactory}.
 */
final class RotationRun
{
    /**
     * Version of the {@see snapshot()} layout.
     */
    public const SNAPSHOT_FORMAT = 1;

    /**
     * How every moment is written in a snapshot: ISO 8601 with microseconds and the UTC offset.
     */
    public const TIMESTAMP_FORMAT = 'Y-m-d\TH:i:s.uP';

    private const FINGERPRINT_SHAPE = '/^[0-9a-f]{16}$/D';

    private const STATES_WITH_NEW_INDEX = [
        RunState::KeyPending, RunState::KeyAdded, RunState::WebConfirmed, RunState::Reencrypted,
        RunState::RetirePending, RunState::Retired,
    ];
    private const STATES_WITH_RING_WRITE = [
        RunState::KeyAdded, RunState::WebConfirmed, RunState::Reencrypted, RunState::RetirePending,
        RunState::Retired,
    ];
    private const STATES_WITH_SUMMARY = [RunState::Reencrypted, RunState::RetirePending, RunState::Retired];
    private const PENDING_STATES = [RunState::KeyPending, RunState::RetirePending];
    private const ROLLBACK_STATES = [RunState::RollingBack, RunState::RolledBack];

    private RunState $state;

    /**
     * @var list<int>
     */
    private readonly array $oldUsableIndices;

    private string $ringFingerprint;

    /**
     * @var list<array{override: RunOverride, state: RunState, at: \DateTimeImmutable}>
     */
    private array $overrides;

    /**
     * @var list<array{state: RunState, at: \DateTimeImmutable}>
     */
    private array $history;

    /**
     * @param RunId                   $id                      the run
     * @param string                  $ringFingerprintBefore   fingerprint of the key ring before the run
     * @param list<int>               $oldUsableIndices        the indices below the active one that held a key before the run
     * @param int                     $activeIndexBefore       the active index before the run
     * @param \DateTimeImmutable      $startedAt               when the run started
     * @param RunState                $state                   where the run stands
     * @param int|null                $newIndex                the index of the appended key, once announced
     * @param string|null             $ringFingerprint         fingerprint of the ring the run last recorded; the ring before the run when null
     * @param string|null             $intendedRingFingerprint fingerprint of the ring a pending write is about to write
     * @param \DateTimeImmutable|null $lastRingWriteAt         when the run last wrote the ring
     * @param bool                    $probeSkipped            whether the web tier check of the appended key was skipped
     * @param ScanSummary|null        $lastSummary             what the last scan left behind
     * @param bool                    $configCacheCleaned      whether the configuration cache was cleaned after the last re-encryption
     * @param RunState|null           $rolledBackFrom          the state a rollback started from
     * @param list<array{override: RunOverride, state: RunState, at: \DateTimeImmutable}>     $overrides               the waived checks, in the order they were given
     * @param list<array{state: RunState, at: \DateTimeImmutable}>      $history                 every recorded state, oldest first; a run that only starts begins with `started`
     *
     * @throws InvalidRun when the fields do not describe a run
     */
    public function __construct(
        private readonly RunId $id,
        private readonly string $ringFingerprintBefore,
        array $oldUsableIndices,
        private readonly int $activeIndexBefore,
        private readonly \DateTimeImmutable $startedAt,
        RunState $state = RunState::Started,
        private ?int $newIndex = null,
        ?string $ringFingerprint = null,
        private ?string $intendedRingFingerprint = null,
        private ?\DateTimeImmutable $lastRingWriteAt = null,
        private bool $probeSkipped = false,
        private ?ScanSummary $lastSummary = null,
        private bool $configCacheCleaned = false,
        private ?RunState $rolledBackFrom = null,
        array $overrides = [],
        array $history = [],
    ) {
        $this->requireFingerprintShape($ringFingerprintBefore, 'before the run');
        if ($activeIndexBefore < 0 || $activeIndexBefore >= Ciphertext::MAX_KEY_INDEX) {
            throw new InvalidRun(sprintf('The active index before a run lies between 0 and %d; %d was given.', Ciphertext::MAX_KEY_INDEX - 1, $activeIndexBefore));
        }
        $this->oldUsableIndices = $this->validOldIndices($oldUsableIndices, $activeIndexBefore);
        $this->requireNewIndexInPlace($newIndex);
        $this->ringFingerprint = $ringFingerprint ?? $ringFingerprintBefore;
        $this->requireFingerprintShape($this->ringFingerprint, 'last recorded');
        if ($intendedRingFingerprint !== null) {
            $this->requireFingerprintShape($intendedRingFingerprint, 'intended');
        }
        $this->state = $state;
        $this->requireStateFacts();
        $this->overrides = $overrides;
        $this->history = $history === [] ? [['state' => RunState::Started, 'at' => $startedAt]] : $history;
        $last = $this->history[count($this->history) - 1];
        if ($last['state'] !== $state) {
            throw new InvalidRun(sprintf('The last recorded state of run %s is "%s", not "%s".', $id->toString(), $last['state']->value, $state->value));
        }
    }

    /**
     * Announces the ring write that appends the new key: the index the key takes and the fingerprint of
     * the ring with it. Recorded again on a resumed run, with the same ring.
     *
     * @throws IllegalRunTransition      when the run is not started or already announcing that write
     * @throws InvalidRun                when the index is not the one after the active index before the run
     * @throws UnexpectedRingFingerprint when a resumed announcement names another ring than the first
     */
    public function keyPending(int $newIndex, string $intendedRingFingerprint, \DateTimeImmutable $at): void
    {
        $this->requireTransition(RunState::KeyPending);
        $this->requireNewIndexInPlace($newIndex);
        $this->requireFingerprintShape($intendedRingFingerprint, 'intended');
        if ($this->state === RunState::KeyPending && $this->intendedRingFingerprint !== $intendedRingFingerprint) {
            throw $this->fingerprintMismatch('announced', (string) $this->intendedRingFingerprint, $intendedRingFingerprint);
        }

        $this->newIndex = $newIndex;
        $this->intendedRingFingerprint = $intendedRingFingerprint;
        $this->record(RunState::KeyPending, $at);
    }

    /**
     * Records that the ring with the new key is written: the ring found must be the announced one.
     *
     * @throws IllegalRunTransition      when no key write is pending
     * @throws UnexpectedRingFingerprint when the ring found is not the announced one
     */
    public function keyAdded(string $ringFingerprint, \DateTimeImmutable $at): void
    {
        $this->requireTransition(RunState::KeyAdded);
        $this->ringWritten($ringFingerprint, $at);
        $this->record(RunState::KeyAdded, $at);
    }

    /**
     * Records that the web tier holds the ring with the new key, or that the check was skipped (which is
     * recorded as an override).
     *
     * @throws IllegalRunTransition when the key is not added yet
     */
    public function webConfirmed(bool $probeSkipped, \DateTimeImmutable $at): void
    {
        $this->requireTransition(RunState::WebConfirmed);
        $this->probeSkipped = $probeSkipped;
        if ($probeSkipped) {
            $this->addOverride(RunOverride::SkipWebProbe, $at);
        }
        $this->record(RunState::WebConfirmed, $at);
    }

    /**
     * Records a re-encryption pass: what the scan after it still found, and whether the configuration
     * cache was cleaned after it. Every further pass is recorded the same way.
     *
     * @throws IllegalRunTransition when the web tier was not confirmed yet
     */
    public function reencrypted(ScanSummary $remaining, bool $configCacheCleaned, \DateTimeImmutable $at): void
    {
        $this->requireTransition(RunState::Reencrypted);
        $this->lastSummary = $remaining;
        $this->configCacheCleaned = $configCacheCleaned;
        $this->record(RunState::Reencrypted, $at);
    }

    /**
     * Announces the ring write that retires the old keys, by the fingerprint of the ring with their
     * placeholders. The first announcement is refused while the last recorded scan blocks retiring and
     * no override covers it; a resumed announcement must name the same ring. Given overrides are
     * recorded.
     *
     * @param list<RunOverride> $overrides the checks the operator waived for this step
     *
     * @throws IllegalRunTransition      when the run is not re-encrypted or already announcing that write
     * @throws RetireRefused             when values would become unreadable or a required step is missing
     * @throws UnexpectedRingFingerprint when a resumed announcement names another ring than the first
     */
    public function retirePending(string $intendedRingFingerprint, array $overrides, \DateTimeImmutable $at): void
    {
        $this->requireTransition(RunState::RetirePending);
        $this->requireFingerprintShape($intendedRingFingerprint, 'intended');
        if ($this->state === RunState::RetirePending) {
            if ($this->intendedRingFingerprint !== $intendedRingFingerprint) {
                throw $this->fingerprintMismatch('announced', (string) $this->intendedRingFingerprint, $intendedRingFingerprint);
            }
        } else {
            $obstacles = $this->retireObstacles($overrides);
            if ($obstacles !== []) {
                throw new RetireRefused(sprintf('Run %s cannot retire the old keys: %s.', $this->id->toString(), implode('; ', $obstacles)));
            }
        }

        foreach ($overrides as $override) {
            $this->addOverride($override, $at);
        }
        $this->intendedRingFingerprint = $intendedRingFingerprint;
        $this->record(RunState::RetirePending, $at);
    }

    /**
     * Records that the ring with the placeholders is written: the ring found must be the announced one.
     *
     * @throws IllegalRunTransition      when no retire write is pending
     * @throws UnexpectedRingFingerprint when the ring found is not the announced one
     */
    public function retired(string $ringFingerprint, \DateTimeImmutable $at): void
    {
        $this->requireTransition(RunState::Retired);
        $this->ringWritten($ringFingerprint, $at);
        $this->record(RunState::Retired, $at);
    }

    /**
     * Starts a rollback, before anything is undone. From then on only the rollback may continue the run;
     * recording it again while it is the state keeps the state it started from.
     *
     * @throws IllegalRunTransition when the run is rolled back or purged
     */
    public function rollingBack(\DateTimeImmutable $at): void
    {
        $this->requireTransition(RunState::RollingBack);
        if ($this->state !== RunState::RollingBack) {
            $this->rolledBackFrom = $this->state;
        }
        $this->record(RunState::RollingBack, $at);
    }

    /**
     * Announces a ring write of the rollback (putting a retired key back, removing the appended key) by
     * the fingerprint of the ring about to be written.
     *
     * @throws IllegalRunTransition when the run is not rolling back
     * @throws InvalidRun           when the fingerprint is malformed
     */
    public function rollbackRingPending(string $intendedRingFingerprint, \DateTimeImmutable $at): void
    {
        $this->requireRollingBack('announce a key ring write');
        $this->requireFingerprintShape($intendedRingFingerprint, 'intended');
        $this->intendedRingFingerprint = $intendedRingFingerprint;
    }

    /**
     * Records a ring write of the rollback: the ring found must be the announced one.
     *
     * @throws IllegalRunTransition      when the run is not rolling back
     * @throws UnexpectedRingFingerprint when no write was announced or the ring found is not the announced one
     */
    public function rollbackRingWritten(string $ringFingerprint, \DateTimeImmutable $at): void
    {
        $this->requireRollingBack('record a key ring write');
        $this->ringWritten($ringFingerprint, $at);
    }

    /**
     * Records that the rollback is complete: the ring found must be the ring the store had before the run.
     *
     * @throws IllegalRunTransition      when the run is not rolling back
     * @throws UnexpectedRingFingerprint when the ring found is not the ring before the run
     */
    public function rolledBack(string $ringFingerprint, \DateTimeImmutable $at): void
    {
        $this->requireTransition(RunState::RolledBack);
        if ($ringFingerprint !== $this->ringFingerprintBefore) {
            throw $this->fingerprintMismatch('held before the run', $this->ringFingerprintBefore, $ringFingerprint);
        }
        $this->ringFingerprint = $ringFingerprint;
        $this->intendedRingFingerprint = null;
        $this->record(RunState::RolledBack, $at);
    }

    /**
     * Records that the run's kept keys and journal are gone; accepting the loss of values only they
     * decrypted is recorded as an override.
     *
     * @throws IllegalRunTransition when the run is neither retired nor rolled back
     */
    public function purged(bool $acceptedLoss, \DateTimeImmutable $at): void
    {
        $this->requireTransition(RunState::Purged);
        if ($acceptedLoss) {
            $this->addOverride(RunOverride::AcceptLoss, $at);
        }
        $this->record(RunState::Purged, $at);
    }

    /**
     * Records a check the operator waived in the current state.
     *
     * @throws IllegalRunTransition when the run is purged
     */
    public function overridden(RunOverride $override, \DateTimeImmutable $at): void
    {
        if ($this->state === RunState::Purged) {
            throw new IllegalRunTransition(sprintf('Run %s is purged; it records nothing more.', $this->id->toString()));
        }
        $this->addOverride($override, $at);
    }

    public function id(): RunId
    {
        return $this->id;
    }

    public function state(): RunState
    {
        return $this->state;
    }

    public function isActive(): bool
    {
        return $this->state->isActive();
    }

    /**
     * Whether a rollback has started and not finished: while it is, only the rollback may continue.
     */
    public function isRollingBack(): bool
    {
        return $this->state === RunState::RollingBack;
    }

    /**
     * The index of the appended key, once its write was announced.
     */
    public function newIndex(): ?int
    {
        return $this->newIndex;
    }

    /**
     * @return list<int> the indices below the active one that held a key before the run
     */
    public function oldUsableIndices(): array
    {
        return $this->oldUsableIndices;
    }

    public function activeIndexBefore(): int
    {
        return $this->activeIndexBefore;
    }

    /**
     * @return list<int> the indices whose values the rotation moves to the new key and whose keys retiring
     *                   replaces: the key that was active before the run and every usable key below it
     */
    public function movedIndices(): array
    {
        $indices = [...$this->oldUsableIndices, $this->activeIndexBefore];
        sort($indices);

        return $indices;
    }

    public function ringFingerprintBefore(): string
    {
        return $this->ringFingerprintBefore;
    }

    /**
     * The fingerprint of the ring the run last recorded: the ring before the run until the run's first
     * ring write is recorded.
     */
    public function ringFingerprint(): string
    {
        return $this->ringFingerprint;
    }

    /**
     * The fingerprint a pending ring write announced, or null when no write is pending.
     */
    public function intendedRingFingerprint(): ?string
    {
        return $this->intendedRingFingerprint;
    }

    /**
     * When the run last wrote the ring; a process that started before it may still hold the earlier ring.
     */
    public function lastRingWriteAt(): ?\DateTimeImmutable
    {
        return $this->lastRingWriteAt;
    }

    public function startedAt(): \DateTimeImmutable
    {
        return $this->startedAt;
    }

    public function probeSkipped(): bool
    {
        return $this->probeSkipped;
    }

    public function lastSummary(): ?ScanSummary
    {
        return $this->lastSummary;
    }

    public function configCacheCleaned(): bool
    {
        return $this->configCacheCleaned;
    }

    /**
     * The state a rollback started from, or null when none started.
     */
    public function rolledBackFrom(): ?RunState
    {
        return $this->rolledBackFrom;
    }

    /**
     * @return list<array{override: RunOverride, state: RunState, at: \DateTimeImmutable}> the waived checks, in the order they were given
     */
    public function overrides(): array
    {
        return $this->overrides;
    }

    /**
     * @return list<array{state: RunState, at: \DateTimeImmutable}> every recorded state, oldest first
     */
    public function history(): array
    {
        return $this->history;
    }

    /**
     * The run as plain data with stable keys, for persistence. It holds fingerprints, indices, counts and
     * moments; never a key.
     *
     * @return array{format: int, id: string, state: string, ring_fingerprint_before: string, old_usable_indices: list<int>, active_index_before: int, started_at: string, new_index: int|null, ring_fingerprint: string, intended_ring_fingerprint: string|null, last_ring_write_at: string|null, probe_skipped: bool, last_summary: array{verified: list<array{index: int, count: int}>, undecryptable: int, embedded: int, incomplete_columns: int, without_row_key: list<array{index: int, count: int}>}|null, config_cache_cleaned: bool, rolled_back_from: string|null, overrides: list<array{override: string, state: string, at: string}>, history: list<array{state: string, at: string}>}
     */
    public function snapshot(): array
    {
        return [
            'format' => self::SNAPSHOT_FORMAT,
            'id' => $this->id->toString(),
            'state' => $this->state->value,
            'ring_fingerprint_before' => $this->ringFingerprintBefore,
            'old_usable_indices' => $this->oldUsableIndices,
            'active_index_before' => $this->activeIndexBefore,
            'started_at' => $this->startedAt->format(self::TIMESTAMP_FORMAT),
            'new_index' => $this->newIndex,
            'ring_fingerprint' => $this->ringFingerprint,
            'intended_ring_fingerprint' => $this->intendedRingFingerprint,
            'last_ring_write_at' => $this->lastRingWriteAt?->format(self::TIMESTAMP_FORMAT),
            'probe_skipped' => $this->probeSkipped,
            'last_summary' => $this->lastSummary?->snapshot(),
            'config_cache_cleaned' => $this->configCacheCleaned,
            'rolled_back_from' => $this->rolledBackFrom?->value,
            'overrides' => array_map(
                static fn(array $entry): array => [
                    'override' => $entry['override']->value,
                    'state' => $entry['state']->value,
                    'at' => $entry['at']->format(self::TIMESTAMP_FORMAT),
                ],
                $this->overrides,
            ),
            'history' => array_map(
                static fn(array $entry): array => [
                    'state' => $entry['state']->value,
                    'at' => $entry['at']->format(self::TIMESTAMP_FORMAT),
                ],
                $this->history,
            ),
        ];
    }

    /**
     * @param list<RunOverride> $overrides
     *
     * @return list<string> why retiring the old keys is refused; empty when nothing stands in the way
     */
    private function retireObstacles(array $overrides): array
    {
        $summary = $this->lastSummary;
        if ($summary === null) {
            return ['no scan was recorded after the re-encryption'];
        }

        $obstacles = [];
        $moved = $this->movedIndices();
        $remaining = $summary->verifiedOnAny($moved);
        $withoutRowKey = $summary->withoutRowKeyOnAny($moved);
        if (!in_array(RunOverride::AcceptRemaining, $overrides, true)) {
            if ($remaining > 0) {
                $obstacles[] = sprintf(
                    '%d values still decrypt under the old key indices %s',
                    $remaining,
                    implode(', ', $moved),
                );
            }
            if ($withoutRowKey > 0) {
                $obstacles[] = sprintf(
                    '%d values under the old key indices %s sit in columns whose table has no row key, which the tool cannot rewrite',
                    $withoutRowKey,
                    implode(', ', $moved),
                );
            }
        }
        if ($summary->hasUnjudgedValues() && !in_array(RunOverride::AcceptEmbedded, $overrides, true)) {
            $obstacles[] = sprintf(
                '%d embedded values and %d columns whose scan was cut short are not acknowledged',
                $summary->embedded(),
                $summary->incompleteColumns(),
            );
        }
        if (!$this->configCacheCleaned && !in_array(RunOverride::CacheCleanedManually, $overrides, true)) {
            $obstacles[] = 'the configuration cache was not cleaned after the last re-encryption';
        }

        return $obstacles;
    }

    private function ringWritten(string $ringFingerprint, \DateTimeImmutable $at): void
    {
        if ($this->intendedRingFingerprint === null) {
            throw new UnexpectedRingFingerprint(sprintf(
                'Run %s announced no key ring write; the ring %s cannot be recorded as written.',
                $this->id->toString(),
                $ringFingerprint,
            ));
        }
        if ($ringFingerprint !== $this->intendedRingFingerprint) {
            throw $this->fingerprintMismatch('announced', $this->intendedRingFingerprint, $ringFingerprint);
        }
        $this->ringFingerprint = $ringFingerprint;
        $this->intendedRingFingerprint = null;
        $this->lastRingWriteAt = $at;
    }

    private function requireTransition(RunState $next): void
    {
        if (!$this->state->allows($next)) {
            throw new IllegalRunTransition(sprintf(
                'Run %s is "%s" and cannot become "%s".',
                $this->id->toString(),
                $this->state->value,
                $next->value,
            ));
        }
    }

    private function requireRollingBack(string $action): void
    {
        if ($this->state !== RunState::RollingBack) {
            throw new IllegalRunTransition(sprintf(
                'Run %s is "%s"; only a run that is "%s" can %s.',
                $this->id->toString(),
                $this->state->value,
                RunState::RollingBack->value,
                $action,
            ));
        }
    }

    private function record(RunState $state, \DateTimeImmutable $at): void
    {
        $this->state = $state;
        $this->history[] = ['state' => $state, 'at' => $at];
    }

    private function addOverride(RunOverride $override, \DateTimeImmutable $at): void
    {
        $this->overrides[] = ['override' => $override, 'state' => $this->state, 'at' => $at];
    }

    private function fingerprintMismatch(string $expectedRole, string $expected, string $found): UnexpectedRingFingerprint
    {
        return new UnexpectedRingFingerprint(sprintf(
            'Run %s expects the key ring %s (%s), not %s.',
            $this->id->toString(),
            $expected,
            $expectedRole,
            $found,
        ));
    }

    private function requireFingerprintShape(string $fingerprint, string $role): void
    {
        if (preg_match(self::FINGERPRINT_SHAPE, $fingerprint) !== 1) {
            throw new InvalidRun(sprintf('A key ring fingerprint (%s) is 16 lowercase hexadecimal characters.', $role));
        }
    }

    private function requireNewIndexInPlace(?int $newIndex): void
    {
        if ($newIndex !== null && $newIndex !== $this->activeIndexBefore + 1) {
            throw new InvalidRun(sprintf(
                'The appended key takes the index after the active one, %d; %d was given.',
                $this->activeIndexBefore + 1,
                $newIndex,
            ));
        }
    }

    /**
     * @param array<array-key, int> $indices
     *
     * @return list<int>
     */
    private function validOldIndices(array $indices, int $activeIndexBefore): array
    {
        $valid = [];
        foreach ($indices as $index) {
            if ($index < 0 || $index >= $activeIndexBefore) {
                throw new InvalidRun(sprintf('An old usable index lies below the active index %d; %d was given.', $activeIndexBefore, $index));
            }
            if (in_array($index, $valid, true)) {
                throw new InvalidRun(sprintf('The old usable index %d is listed twice.', $index));
            }
            $valid[] = $index;
        }
        sort($valid);

        return $valid;
    }

    /**
     * The facts each state needs: an announced new index from key_pending on, a ring write from
     * key_added on, a scan from reencrypted on, an announced ring in the pending states, and the state a
     * rollback started from in the rollback states.
     */
    private function requireStateFacts(): void
    {
        $state = $this->state;
        $missing = match (true) {
            in_array($state, self::STATES_WITH_NEW_INDEX, true) && $this->newIndex === null => 'the index of the appended key',
            in_array($state, self::STATES_WITH_RING_WRITE, true) && $this->lastRingWriteAt === null => 'the moment of the last key ring write',
            in_array($state, self::STATES_WITH_SUMMARY, true) && $this->lastSummary === null => 'the summary of the last scan',
            in_array($state, self::PENDING_STATES, true) && $this->intendedRingFingerprint === null => 'the announced key ring',
            in_array($state, self::ROLLBACK_STATES, true) && $this->rolledBackFrom === null => 'the state the rollback started from',
            default => null,
        };
        if ($missing !== null) {
            throw new InvalidRun(sprintf('A run that is "%s" needs %s.', $state->value, $missing));
        }
        $from = $this->rolledBackFrom;
        if ($from !== null && ($from === RunState::RollingBack || !$from->allows(RunState::RollingBack))) {
            throw new InvalidRun(sprintf('A rollback cannot start from "%s".', $from->value));
        }
    }
}
