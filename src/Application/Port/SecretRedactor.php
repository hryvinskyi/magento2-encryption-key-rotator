<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

/**
 * Removes secrets from text that leaves the tool (an error line, a subprocess's error output): every
 * ciphertext, every run of 32 or more base64 characters and the database password become `[redacted]`.
 */
interface SecretRedactor
{
    public function redact(string $text): string;
}
