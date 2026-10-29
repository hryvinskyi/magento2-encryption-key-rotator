<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Fixtures\Factory\MissingParameter;

final class Badge
{
    public function __construct(
        public readonly string $label,
    ) {}
}
