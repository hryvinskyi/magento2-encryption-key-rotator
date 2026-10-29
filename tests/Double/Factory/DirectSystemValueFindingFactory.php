<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueFinding;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueFindingFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ValueVerdict;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectSystemValueFindingFactory implements SystemValueFindingFactory
{
    public function create(SystemValue $value, ValueVerdict $verdict): SystemValueFinding
    {
        return new SystemValueFinding($value, $verdict);
    }
}
