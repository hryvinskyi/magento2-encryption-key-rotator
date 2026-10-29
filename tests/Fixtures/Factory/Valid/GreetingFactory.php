<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Fixtures\Factory\Valid;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

#[CreatesInstancesOf(Greeting::class)]
interface GreetingFactory
{
    public function create(string $name, int $times): Greeting;

    public function createOnce(string $name, int $times = 1): Greeting;
}
