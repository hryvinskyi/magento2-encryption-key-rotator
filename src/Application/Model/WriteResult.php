<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

/**
 * What one batch of compare-and-swap writes did: how many rows it changed, and the rows it left alone.
 *
 * Created through {@see WriteResultFactory}.
 */
final class WriteResult
{
    /**
     * @param int            $applied   rows changed
     * @param list<Conflict> $conflicts rows left alone
     *
     * @throws InvalidValue when the applied count is negative
     */
    public function __construct(
        private readonly int $applied,
        private readonly array $conflicts,
    ) {
        if ($applied < 0) {
            throw new InvalidValue('An applied count cannot be negative.');
        }
    }

    public function applied(): int
    {
        return $this->applied;
    }

    /**
     * @return list<Conflict>
     */
    public function conflicts(): array
    {
        return $this->conflicts;
    }

    /**
     * Whether every write of the batch happened.
     */
    public function isClean(): bool
    {
        return $this->conflicts === [];
    }
}
