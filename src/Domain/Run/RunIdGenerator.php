<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Run;

/**
 * Draws the id of a new run.
 */
interface RunIdGenerator
{
    /**
     * A new id, unpredictable and practically unique.
     */
    public function next(): RunId;
}
