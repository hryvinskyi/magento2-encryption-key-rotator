<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;

/**
 * Collects the strings of an evaluated configuration array that their path names as secret: every
 * string leaf of at least {@see DeploymentConfigReader::SECRET_MIN_LENGTH} characters under a key whose
 * name contains one of {@see DeploymentConfigReader::SECRET_SEGMENT_WORDS} (a database or queue
 * password, an API secret, the key ring, a token), at any depth below that key.
 */
final class SecretLeaves
{
    /**
     * @param array<mixed> $config the evaluated file
     *
     * @return list<string> each secret string once, in the order of the file
     */
    public function collect(array $config): array
    {
        $found = [];
        $this->walk($config, false, $found);

        return array_keys($found);
    }

    /**
     * @param array<mixed>        $node
     * @param array<string, true> $found
     */
    private function walk(array $node, bool $underSecretKey, array &$found): void
    {
        foreach ($node as $key => $value) {
            $secret = $underSecretKey || $this->namesSecret((string) $key);
            if (is_array($value)) {
                $this->walk($value, $secret, $found);

                continue;
            }
            if ($secret && is_string($value) && strlen($value) >= DeploymentConfigReader::SECRET_MIN_LENGTH) {
                $found[$value] = true;
            }
        }
    }

    private function namesSecret(string $segment): bool
    {
        $segment = strtolower($segment);
        foreach (DeploymentConfigReader::SECRET_SEGMENT_WORDS as $word) {
            if (str_contains($segment, $word)) {
                return true;
            }
        }

        return false;
    }
}
