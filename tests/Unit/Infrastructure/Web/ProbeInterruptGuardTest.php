<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Infrastructure\Web;

use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\ProbeInterruptGuard;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\ProbeScriptWriter;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TemporaryDirectory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Process\Process;

/**
 * A process interrupted while its probe file is in place deletes the file before it ends, and the guard
 * leaves the process's own signal handling as it found it.
 */
final class ProbeInterruptGuardTest extends TestCase
{
    private const CHILD = __DIR__ . '/../../../Fixtures/Web/guarded-probe.php';

    private string $directory;

    protected function setUp(): void
    {
        $this->directory = TemporaryDirectory::create('key-rotator-guarded-probe');
    }

    protected function tearDown(): void
    {
        TemporaryDirectory::remove($this->directory);
    }

    public function testTheWorkRunsAndItsResultIsReturned(): void
    {
        $guard = new ProbeInterruptGuard(new ProbeScriptWriter());
        $answer = bin2hex(random_bytes(4));

        self::assertSame($answer, $guard->protect($this->directory . '/x.php', static fn(): string => $answer));
    }

    /**
     * @return iterable<string, array{int, int}>
     */
    public static function interruptions(): iterable
    {
        yield 'SIGINT, as Ctrl-C sends' => [2, 130];
        yield 'SIGTERM, as kill sends' => [15, 143];
        yield 'SIGHUP, as a closed terminal sends' => [1, 129];
    }

    #[DataProvider('interruptions')]
    #[RequiresPhpExtension('pcntl')]
    public function testAnInterruptedProbeDeletesItsFileAndEndsAsTheSignalWould(int $signal, int $exitCode): void
    {
        $child = $this->startChild();
        $path = $this->waitForProbeFile($child);
        self::assertFileExists($path);

        $child->signal($signal);
        $child->wait();

        self::assertSame($exitCode, $child->getExitCode());
        self::assertFileDoesNotExist($path);
        self::assertSame(['.', '..'], scandir($this->directory));
    }

    #[RequiresPhpExtension('pcntl')]
    public function testASignalTheProcessIgnoredStaysIgnored(): void
    {
        $child = $this->startChild('ignore-hup');
        $path = $this->waitForProbeFile($child);

        $child->signal(1);
        $child->wait();

        self::assertSame(0, $child->getExitCode());
        self::assertStringContainsString('survived', $child->getOutput());
        self::assertFileExists($path, 'The ignored signal did not delete the file; the work did not delete it either.');
    }

    private function startChild(string ...$arguments): Process
    {
        $child = new Process([PHP_BINARY, self::CHILD, $this->directory, ...$arguments]);
        $child->setTimeout(30);
        $child->start();

        return $child;
    }

    private function waitForProbeFile(Process $child): string
    {
        $child->waitUntil(static fn(string $type, string $output): bool => str_contains($output, "\n"));

        return trim(explode("\n", $child->getOutput())[0]);
    }
}
