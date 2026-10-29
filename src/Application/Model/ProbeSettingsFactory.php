<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see ProbeSettings} values; implemented by the container build.
 */
#[CreatesInstancesOf(ProbeSettings::class)]
interface ProbeSettingsFactory
{
    /**
     * @throws InvalidValue when the settings are contradictory or malformed
     */
    public function create(
        ?string $fastCgiAddress,
        ?string $baseUrl,
        ?string $hostHeader,
        string $docroot,
        bool $verifyTls,
        int $waitSeconds,
        bool $skipped,
    ): ProbeSettings;
}
