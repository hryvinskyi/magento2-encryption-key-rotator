<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Requirements;

/**
 * Checks the running PHP against what the tool needs to rotate a key: the PHP version it runs on and the
 * extensions for authenticated encryption, the database connection and JSON.
 */
interface RuntimeRequirements
{
    public function check(): RequirementsReport;
}
