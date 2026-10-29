<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run;

use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunIdFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunIdGenerator;

/**
 * Draws run ids from 16 bytes of the operating system's cryptographically secure generator.
 */
final class RandomRunIdGenerator implements RunIdGenerator
{
    private const BYTES = 16;

    public function __construct(
        private readonly RunIdFactory $ids,
    ) {}

    public function next(): RunId
    {
        return $this->ids->create(bin2hex(random_bytes(self::BYTES)));
    }
}
