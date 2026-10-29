<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunIdFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectRunIdFactory implements RunIdFactory
{
    public function create(string $value): RunId
    {
        return new RunId($value);
    }
}
