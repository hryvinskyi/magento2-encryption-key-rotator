<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\WriteResult;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\WriteResultFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectWriteResultFactory implements WriteResultFactory
{
    public function create(int $applied, array $conflicts): WriteResult
    {
        return new WriteResult($applied, $conflicts);
    }
}
