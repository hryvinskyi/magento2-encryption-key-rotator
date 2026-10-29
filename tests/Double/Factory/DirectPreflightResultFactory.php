<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Preflight\PreflightResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Preflight\PreflightResultFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectPreflightResultFactory implements PreflightResultFactory
{
    public function create(array $refusals, array $workers, array $waived): PreflightResult
    {
        return new PreflightResult($refusals, $workers, $waived);
    }
}
