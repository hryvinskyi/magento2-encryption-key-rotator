<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\InvalidValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;

/**
 * What the operator asked a rotation to do:
 * - a dry run only scans and reports the plan;
 * - the raw ring entry of the key to append, when the operator supplies one, otherwise a new random key
 *   is drawn (a resumed run always writes the key it kept, never another);
 * - how many values move at once (a rotation always covers every column, so the retirement and the
 *   rollback that follow it never meet a column it skipped);
 * - whether processes that may hold an earlier key ring may keep running, and whether the tool may run as
 *   another user than the owner of the deployment configuration, both recorded on the run when they
 *   waive something;
 * - how the web tier is asked which ring it holds, the skip included.
 *
 * The key entry never prints itself and is never serialised. Created through {@see RotateRequestFactory}.
 */
final class RotateRequest
{
    public const DEFAULT_BATCH_SIZE = 500;

    /**
     * @throws InvalidValue when the batch size is below 1 or the key entry is empty
     */
    public function __construct(
        private readonly bool $dryRun,
        #[\SensitiveParameter]
        private readonly ?string $rawKey,
        private readonly int $batchSize,
        private readonly bool $ignoreWorkers,
        private readonly bool $allowOtherUser,
        private readonly ProbeSettings $probeSettings,
    ) {
        if ($batchSize < 1) {
            throw new InvalidValue('A rotation moves at least one value at a time.');
        }
        if ($rawKey === '') {
            throw new InvalidValue('A key given for a rotation cannot be empty.');
        }
    }

    public function isDryRun(): bool
    {
        return $this->dryRun;
    }

    /**
     * The ring entry of the key the operator supplied, or null when the rotation draws one.
     */
    public function rawKey(): ?string
    {
        return $this->rawKey;
    }

    public function batchSize(): int
    {
        return $this->batchSize;
    }

    public function ignoresWorkers(): bool
    {
        return $this->ignoreWorkers;
    }

    public function allowsOtherUser(): bool
    {
        return $this->allowOtherUser;
    }

    public function probeSettings(): ProbeSettings
    {
        return $this->probeSettings;
    }

    /**
     * @return array{dryRun: bool, rawKey: string|null, batchSize: int, ignoreWorkers: bool, allowOtherUser: bool}
     */
    public function __debugInfo(): array
    {
        return [
            'dryRun' => $this->dryRun,
            'rawKey' => $this->rawKey === null ? null : '[redacted]',
            'batchSize' => $this->batchSize,
            'ignoreWorkers' => $this->ignoreWorkers,
            'allowOtherUser' => $this->allowOtherUser,
        ];
    }

    /**
     * @return array<string, mixed>
     *
     * @throws \LogicException always: the request may hold key material, which is never serialised
     */
    public function __serialize(): array
    {
        throw new \LogicException('A rotation request cannot be serialised.');
    }

    /**
     * @param array<string, mixed> $data
     *
     * @throws \LogicException always: a request is never restored from serialised data
     */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('A rotation request cannot be unserialised.');
    }
}
