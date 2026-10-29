<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Fixtures\Factory\UnwirableScalar;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

#[CreatesInstancesOf(Batch::class)]
interface BatchFactory
{
    public function create(string $name): Batch;
}
