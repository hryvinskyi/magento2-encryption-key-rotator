<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\SecretRedactor;

/**
 * Returns text unchanged, and remembers what it was given, so a test can check what a use case passed
 * through the redactor.
 */
final class PassThroughSecretRedactor implements SecretRedactor
{
    /**
     * @var list<string>
     */
    private array $seen = [];

    public function redact(string $text): string
    {
        $this->seen[] = $text;

        return $text;
    }

    /**
     * @return list<string>
     */
    public function seen(): array
    {
        return $this->seen;
    }
}
