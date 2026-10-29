<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Key;

/**
 * A change of the key ring that would break one of its rules: retiring the active key, retiring or
 * restoring the wrong slot, removing a slot that is not the one expected, or appending a key the ring
 * cannot take. The ring the change was asked of stays as it was.
 */
final class KeyRingChangeRefused extends \DomainException {}
