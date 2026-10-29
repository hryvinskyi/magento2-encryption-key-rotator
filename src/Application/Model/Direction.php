<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

/**
 * Which way a re-encryption moves values: forward onto the appended key, or back onto the key that was
 * active before the run.
 */
enum Direction: string
{
    case Forward = 'forward';
    case Back = 'back';
}
