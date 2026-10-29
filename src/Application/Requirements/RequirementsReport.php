<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Requirements;

/**
 * What the running PHP offers against what the tool needs: its version and, per required extension,
 * whether it is loaded.
 */
final class RequirementsReport
{
    /**
     * @param string              $phpVersion the running PHP version
     * @param array<string, bool> $extensions required extension name => whether it is loaded
     */
    public function __construct(
        private readonly string $phpVersion,
        private readonly array $extensions,
    ) {}

    public function phpVersion(): string
    {
        return $this->phpVersion;
    }

    /**
     * @return array<string, bool> required extension name => whether it is loaded
     */
    public function extensions(): array
    {
        return $this->extensions;
    }

    /**
     * @return list<string> the required extensions that are not loaded
     */
    public function missingExtensions(): array
    {
        return array_keys(array_filter($this->extensions, static fn(bool $loaded): bool => !$loaded));
    }

    public function isSatisfied(): bool
    {
        return $this->missingExtensions() === [];
    }
}
