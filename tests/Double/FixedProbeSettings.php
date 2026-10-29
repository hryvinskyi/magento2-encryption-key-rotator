<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ProbeSettingsProvider;

/**
 * The probe settings a test names; by default a FastCGI probe with no wait.
 */
final class FixedProbeSettings implements ProbeSettingsProvider
{
    public function __construct(
        private ProbeSettings $settings = new ProbeSettings('unix:///run/php-fpm.sock', null, null, ProbeSettings::DEFAULT_DOCROOT, true, 0, false),
    ) {}

    public function settings(): ProbeSettings
    {
        return $this->settings;
    }

    public function replace(ProbeSettings $settings): void
    {
        $this->settings = $settings;
    }
}
