<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Requirements;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates requirement reports; implemented by the container build.
 */
#[CreatesInstancesOf(RequirementsReport::class)]
interface RequirementsReportFactory
{
    /**
     * @param array<string, bool> $extensions required extension name => whether it is loaded
     */
    public function create(string $phpVersion, array $extensions): RequirementsReport;
}
