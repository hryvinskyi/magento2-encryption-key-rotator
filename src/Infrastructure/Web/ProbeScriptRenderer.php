<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web;

/**
 * Renders the probe file from its template (`probe.php.tpl`, beside this class).
 *
 * The rendered file includes the deployment configuration by its absolute path and reads `crypt/key`
 * the way the tool reads a key ring: surrounding whitespace dropped, entries split on whitespace and
 * joined by a newline. It answers a request carrying `t=<token>` with the HMAC-SHA256 of that ring under
 * the token, every other request with 404 and an empty body, and never lets a response be cached.
 */
final class ProbeScriptRenderer
{
    private const TEMPLATE = __DIR__ . '/probe.php.tpl';

    /**
     * @param string $deploymentConfigFile the absolute path of `app/etc/env.php`
     * @param string $token                the token the probe answers to and keys its HMAC with
     *
     * @throws ProbeUnreachable when the template cannot be read
     */
    public function render(string $deploymentConfigFile, #[\SensitiveParameter] string $token): string
    {
        $template = @file_get_contents(self::TEMPLATE);
        if ($template === false) {
            throw new ProbeUnreachable(sprintf('The probe template %s cannot be read.', self::TEMPLATE));
        }

        return strtr($template, [
            '{{token}}' => var_export($token, true),
            '{{deploymentConfig}}' => var_export($deploymentConfigFile, true),
        ]);
    }
}
