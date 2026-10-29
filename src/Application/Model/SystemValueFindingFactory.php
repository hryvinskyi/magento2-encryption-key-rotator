<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see SystemValueFinding} values; implemented by the container build.
 */
#[CreatesInstancesOf(SystemValueFinding::class)]
interface SystemValueFindingFactory
{
    public function create(SystemValue $value, ValueVerdict $verdict): SystemValueFinding;
}
