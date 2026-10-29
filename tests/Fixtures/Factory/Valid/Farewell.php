<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Fixtures\Factory\Valid;

final class Farewell
{
    public function __construct(
        public readonly string $name,
    ) {}
}
