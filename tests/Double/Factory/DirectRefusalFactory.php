<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\Refusal;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\RefusalFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\RefusalReason;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectRefusalFactory implements RefusalFactory
{
    public function create(RefusalReason $reason, string $message): Refusal
    {
        return new Refusal($reason, $message);
    }
}
