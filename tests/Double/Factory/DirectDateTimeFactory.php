<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Run\DateTimeFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectDateTimeFactory implements DateTimeFactory
{
    public function create(string $datetime): \DateTimeImmutable
    {
        return new \DateTimeImmutable($datetime);
    }
}
