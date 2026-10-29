<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Fixtures\Factory\TypeMismatch;

final class Counter
{
    public function __construct(
        public readonly int $start,
    ) {}
}
