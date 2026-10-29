<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Fixtures\Factory\NonShared;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

#[CreatesInstancesOf(Document::class)]
interface DocumentFactory
{
    public function create(string $title): Document;
}
