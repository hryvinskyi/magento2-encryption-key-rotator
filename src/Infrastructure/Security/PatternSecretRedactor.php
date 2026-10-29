<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Security;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\SecretRedactor;

/**
 * Redacts by value and by pattern:
 * - the secrets of the deployment configuration wherever they appear: the database password, and every
 *   string the file's names mark as secret ({@see DeploymentConfigReader::secretStrings()}: a queue or
 *   cache password, an API secret, a token, the key ring), as written and as JSON writes them;
 * - every ciphertext (`<key index>:<cipher version>:<base64>`);
 * - every run of 32 or more base64 characters, which covers key entries, decoded keys printed as text and
 *   ciphertext payloads quoted without their prefix. A long path without punctuation is such a run too
 *   and is redacted with them: the redactor errs on the side of hiding.
 * Ciphertexts and base64 runs are found also when JSON escaped their slashes (`\/`), as in a JSON error
 * body a subprocess or the web tier sends back.
 *
 * The secrets are read from the deployment configuration the first time text is redacted, never
 * earlier: the store is known only once a command runs; they are then kept for every later call. When
 * they cannot be read (the file is the very thing that failed), the patterns still apply and the next
 * call tries again. Redacting never throws, since it runs while an error is being reported.
 */
final class PatternSecretRedactor implements SecretRedactor
{
    public const REDACTED = '[redacted]';

    private const BASE64_CHARACTER = '(?:[A-Za-z0-9+/]|\\\\/)';
    private const CIPHERTEXT = '~(?<![A-Za-z0-9+/\\\\])\d{1,3}:\d:' . self::BASE64_CHARACTER . '{16,}={0,2}~';
    private const BASE64_RUN = '~' . self::BASE64_CHARACTER . '{32,}={0,2}~';

    /**
     * @var list<string>|null every form of every secret to replace, longest first; null until read
     */
    private ?array $secrets = null;

    public function __construct(
        private readonly DeploymentConfigReader $deploymentConfig,
    ) {}

    public function redact(string $text): string
    {
        foreach ($this->secrets() as $secret) {
            $text = str_replace($secret, self::REDACTED, $text);
        }

        $text = preg_replace(self::CIPHERTEXT, self::REDACTED, $text);
        if ($text === null) {
            return self::REDACTED;
        }

        return preg_replace(self::BASE64_RUN, self::REDACTED, $text) ?? self::REDACTED;
    }

    /**
     * @return array{secrets: string}
     */
    public function __debugInfo(): array
    {
        return ['secrets' => self::REDACTED];
    }

    /**
     * @return list<string>
     */
    private function secrets(): array
    {
        if ($this->secrets !== null) {
            return $this->secrets;
        }
        try {
            $values = [$this->deploymentConfig->databaseSettings()->password(), ...$this->deploymentConfig->secretStrings()];
        } catch (\Throwable) {
            // Whatever made the configuration unreadable is being reported right now; the secrets stay
            // unknown until a later call can read them.
            return [];
        }

        $forms = [];
        foreach ($values as $value) {
            if ($value === '') {
                continue;
            }
            $forms[$value] = true;
            $encoded = json_encode($value, JSON_UNESCAPED_UNICODE);
            if (is_string($encoded) && strlen($encoded) > 2) {
                $forms[substr($encoded, 1, -1)] = true;
            }
        }
        $secrets = array_map('strval', array_keys($forms));
        usort($secrets, static fn(string $a, string $b): int => strlen($b) <=> strlen($a));

        return $this->secrets = $secrets;
    }
}
