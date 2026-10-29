<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Run;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates moments from their written form; implemented by the container build. The current moment comes
 * from the clock, never from here.
 */
#[CreatesInstancesOf(\DateTimeImmutable::class)]
interface DateTimeFactory
{
    /**
     * @param string $datetime a moment with its UTC offset, as a run snapshot writes it
     *
     * @throws \Exception when the text is not a moment
     */
    public function create(string $datetime): \DateTimeImmutable;
}
