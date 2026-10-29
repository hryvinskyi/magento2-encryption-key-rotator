<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettingsFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectProbeSettingsFactory implements ProbeSettingsFactory
{
    public function create(
        ?string $fastCgiAddress,
        ?string $baseUrl,
        ?string $hostHeader,
        string $docroot,
        bool $verifyTls,
        int $waitSeconds,
        bool $skipped,
    ): ProbeSettings {
        return new ProbeSettings($fastCgiAddress, $baseUrl, $hostHeader, $docroot, $verifyTls, $waitSeconds, $skipped);
    }
}
