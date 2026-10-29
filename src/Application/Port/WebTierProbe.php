<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeOutcome;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;

/**
 * Asks the web tier which key ring it holds, through the transport the command's
 * {@see ProbeSettingsProvider} names. The web tier may hold an older copy of the deployment
 * configuration than the file on disk, for instance while an opcode cache keeps one.
 */
interface WebTierProbe
{
    /**
     * Whether the web tier holds exactly that ring. The answer proves it without revealing the ring.
     */
    public function observe(KeyRing $expected): ProbeOutcome;
}
