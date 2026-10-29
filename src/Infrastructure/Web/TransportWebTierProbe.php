<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeOutcomeFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeStatus;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\MagentoRootProvider;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ProbeSettingsProvider;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\Progress;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\WebTierProbe;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;

/**
 * Proves which key ring the web tier's PHP holds by running a one-time probe file inside it.
 *
 * Every observation writes a file with a random name that knows a random one-time token, has the
 * transport the probe settings name run it, and deletes it again whatever happened. The file answers
 * with the HMAC of the ring the web tier's PHP sees, keyed by the token; the tool compares it with the
 * HMAC of the expected ring. The answer proves equality without either side revealing the ring, and is
 * worthless after the request. A file that cannot be deleted is reported as a warning naming its path.
 *
 * Before the file is written, the probe files an interrupted earlier probe left in the same directory
 * are deleted ({@see ProbeScriptWriter::sweep()}); one that cannot be is reported as a warning. While the
 * file is in place, an interrupting signal deletes it before the process ends ({@see ProbeInterruptGuard}).
 *
 * The token travels in the query string, so it appears in the access log of the web server or of
 * PHP-FPM; it is worthless once the probe file it belongs to is gone.
 *
 * The transport is the first collected one that supports the settings; none is an unreachable web tier.
 */
final class TransportWebTierProbe implements WebTierProbe
{
    /**
     * More than any answer of the probe file, which is 64 hex characters.
     */
    public const MAX_ANSWER_BYTES = 128;

    private const ANSWER = '/^[0-9a-f]{64}$/D';

    /**
     * @param iterable<ProbeTransport> $transports every transport the container collects
     */
    public function __construct(
        private readonly iterable $transports,
        private readonly ProbeSettingsProvider $settings,
        private readonly MagentoRootProvider $roots,
        private readonly ProbeScriptRenderer $renderer,
        private readonly ProbeScriptWriter $writer,
        private readonly ProbeInterruptGuard $guard,
        private readonly ProbeOutcomeFactory $outcomes,
        private readonly Progress $progress,
    ) {}

    public function observe(KeyRing $expected): ProbeOutcome
    {
        $settings = $this->settings->settings();
        $transport = $this->transportFor($settings);
        if ($transport === null) {
            return $this->unreachable('No probe transport configured: give --probe-fcgi or --probe-url.');
        }

        $name = $this->writer->newFileName();
        $token = bin2hex(random_bytes(32));
        try {
            $directory = $transport->scriptDirectory($settings);
        } catch (ProbeUnreachable $unreachable) {
            return $this->unreachable($unreachable->getMessage());
        }
        foreach ($this->writer->sweep($directory) as $stale) {
            $this->warnUndeleted($stale);
        }

        $path = $directory . '/' . $name;

        return $this->guard->protect($path, function () use ($transport, $settings, $directory, $name, $path, $token, $expected): ProbeOutcome {
            try {
                $this->writer->write($path, $this->renderer->render($this->roots->root()->deploymentConfigFile(), $token));

                return $this->judge($transport->fetch($settings, $directory, $name, 't=' . $token), $expected, $token);
            } catch (ProbeUnreachable $unreachable) {
                return $this->unreachable($unreachable->getMessage());
            } finally {
                if (!$this->writer->remove($path)) {
                    $this->warnUndeleted($path);
                }
            }
        });
    }

    private function warnUndeleted(string $path): void
    {
        $this->progress->warn(sprintf('The web tier probe file %s could not be deleted; delete it by hand.', $path));
    }

    private function transportFor(ProbeSettings $settings): ?ProbeTransport
    {
        foreach ($this->transports as $transport) {
            if ($transport->supports($settings)) {
                return $transport;
            }
        }

        return null;
    }

    private function judge(string $answer, KeyRing $expected, #[\SensitiveParameter] string $token): ProbeOutcome
    {
        if (strlen($answer) > self::MAX_ANSWER_BYTES) {
            return $this->unreachable(sprintf(
                'The web tier answered with %d bytes, more than the probe ever sends: the request did not run the probe file.',
                strlen($answer),
            ));
        }
        if (preg_match(self::ANSWER, $answer) !== 1) {
            return $this->unreachable('The web tier did not answer as the probe file does: the request did not run the probe file.');
        }
        if (!hash_equals(hash_hmac('sha256', $expected->export(), $token), $answer)) {
            return $this->outcomes->create(
                ProbeStatus::Differs,
                'The web tier serves a different key ring — reload PHP-FPM or reset opcache.',
            );
        }

        return $this->outcomes->create(ProbeStatus::Matches, 'The web tier holds the expected key ring.');
    }

    private function unreachable(string $reason): ProbeOutcome
    {
        return $this->outcomes->create(ProbeStatus::Unreachable, $reason);
    }
}
