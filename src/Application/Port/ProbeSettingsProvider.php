<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;

/**
 * The probe settings of the running command, known only once the command has read its options.
 */
interface ProbeSettingsProvider
{
    public function settings(): ProbeSettings;
}
