<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueChange;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueChangeFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Ciphertext;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectSystemValueChangeFactory implements SystemValueChangeFactory
{
    public function create(array $path, Ciphertext $expectedOld, Ciphertext $new): SystemValueChange
    {
        return new SystemValueChange($path, $expectedOld, $new);
    }
}
