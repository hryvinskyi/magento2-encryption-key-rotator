<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Fixtures\Factory\Valid;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

#[CreatesInstancesOf(Farewell::class)]
interface FarewellFactory
{
    public function create(string $name): Farewell;
}
