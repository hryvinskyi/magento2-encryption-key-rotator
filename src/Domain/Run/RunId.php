<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Run;

/**
 * Identifies one rotation: 32 lowercase hexadecimal characters. It names the run directory and tags
 * every journal row the run writes.
 *
 * Created through {@see RunIdFactory}; a new one is drawn by {@see RunIdGenerator}.
 */
final class RunId
{
    private const SHAPE = '/^[0-9a-f]{32}$/D';

    /**
     * @throws InvalidRunId when the value is not 32 lowercase hexadecimal characters
     */
    public function __construct(
        private readonly string $value,
    ) {
        if (preg_match(self::SHAPE, $value) !== 1) {
            throw new InvalidRunId('A run id is 32 lowercase hexadecimal characters.');
        }
    }

    public function toString(): string
    {
        return $this->value;
    }

    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }
}
