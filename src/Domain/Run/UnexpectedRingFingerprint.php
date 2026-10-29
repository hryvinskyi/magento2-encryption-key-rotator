<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Run;

/**
 * A key ring fingerprint other than the one the run expects: the ring a pending write announced, or
 * the ring the store had before the run. The message names both fingerprints.
 */
final class UnexpectedRingFingerprint extends \DomainException {}
