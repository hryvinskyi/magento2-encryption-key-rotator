<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

/**
 * What the web tier answered: it holds the expected key ring, it holds another one, or it could not be
 * asked.
 */
enum ProbeStatus: string
{
    case Matches = 'matches';
    case Differs = 'differs';
    case Unreachable = 'unreachable';
}
