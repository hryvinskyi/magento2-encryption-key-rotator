<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeTransportKind;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\ProbeTransport;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\ProbeUnreachable;

/**
 * A probe transport that plays a web tier holding a given key ring: it answers with the HMAC of that
 * ring under the token of the query, as the probe file would. It supports the transport kind it is
 * given, writes into the directory it is given, and records what it saw of the probe file while it
 * existed. It can instead answer with a body of the test's choosing, fail, or swap the file for a
 * directory that cannot be deleted as a file.
 */
final class RingAnsweringProbeTransport implements ProbeTransport
{
    private ?string $answer = null;

    private ?string $failure = null;

    private bool $replaceWithDirectory = false;

    /**
     * @var list<array{path: string, existed: bool, mode: int|null, source: string, query: string}>
     */
    private array $fetches = [];

    /**
     * @param string $ring the exported key ring the played web tier holds
     */
    public function __construct(
        private readonly ProbeTransportKind $kind,
        private readonly string $directory,
        private string $ring,
    ) {}

    public function supports(ProbeSettings $settings): bool
    {
        return $settings->transport() === $this->kind;
    }

    public function scriptDirectory(ProbeSettings $settings): string
    {
        return $this->directory;
    }

    public function fetch(ProbeSettings $settings, string $directory, string $fileName, string $query): string
    {
        $path = $directory . '/' . $fileName;
        $existed = is_file($path);
        $this->fetches[] = [
            'path' => $path,
            'existed' => $existed,
            'mode' => $existed ? fileperms($path) & 0777 : null,
            'source' => $existed ? (string) file_get_contents($path) : '',
            'query' => $query,
        ];
        if ($this->replaceWithDirectory) {
            unlink($path);
            mkdir($path);
        }
        if ($this->failure !== null) {
            throw new ProbeUnreachable($this->failure);
        }
        if ($this->answer !== null) {
            return $this->answer;
        }
        parse_str($query, $parameters);
        $token = $parameters['t'] ?? '';

        return hash_hmac('sha256', $this->ring, is_string($token) ? $token : '');
    }

    public function holdRing(string $ring): void
    {
        $this->ring = $ring;
    }

    public function answerWith(string $body): void
    {
        $this->answer = $body;
    }

    /**
     * Swaps the probe file for a directory of the same name once it was seen, so it cannot be deleted
     * as a file: the test removes it.
     */
    public function replaceProbeFileWithDirectory(): void
    {
        $this->replaceWithDirectory = true;
    }

    public function failWith(string $reason): void
    {
        $this->failure = $reason;
    }

    /**
     * @return list<array{path: string, existed: bool, mode: int|null, source: string, query: string}>
     */
    public function fetches(): array
    {
        return $this->fetches;
    }
}
