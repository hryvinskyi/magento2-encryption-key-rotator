<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Fixtures\Factory\UnwirableScalar;

final class Batch
{
    public function __construct(
        public readonly string $name,
        public readonly int $size,
    ) {}
}
