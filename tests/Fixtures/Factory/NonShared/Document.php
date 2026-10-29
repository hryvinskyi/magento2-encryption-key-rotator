<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Fixtures\Factory\NonShared;

final class Document
{
    public function __construct(
        public readonly string $title,
        public readonly Stamp $stamp,
    ) {}
}
