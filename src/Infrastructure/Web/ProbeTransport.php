<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;

/**
 * One way of running the probe file inside the web tier's PHP. A transport says whether the probe
 * settings name it, where the probe file must be written so that it can run it, and runs it.
 */
interface ProbeTransport
{
    public function supports(ProbeSettings $settings): bool;

    /**
     * The absolute directory the probe file goes into; the transport may create it.
     *
     * @throws ProbeUnreachable when the settings or the directory rule the probe out
     */
    public function scriptDirectory(ProbeSettings $settings): string;

    /**
     * Runs the probe file in the web tier and returns the body of a successful answer.
     *
     * @param string $directory the directory {@see scriptDirectory()} returned, holding the file
     * @param string $fileName  the probe file's name, inside that directory
     * @param string $query     the query string the probe file expects, without `?`
     *
     * @throws ProbeUnreachable when the web tier cannot be reached, does not answer in time or refuses
     *                          to run the file; the message names what happened, by status line or
     *                          code only
     */
    public function fetch(ProbeSettings $settings, string $directory, string $fileName, string $query): string;
}
