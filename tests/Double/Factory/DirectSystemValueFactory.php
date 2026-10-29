<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueSource;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Ciphertext;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectSystemValueFactory implements SystemValueFactory
{
    public function create(array $path, Ciphertext $ciphertext, SystemValueSource $source): SystemValue
    {
        return new SystemValue($path, $ciphertext, $source);
    }
}
