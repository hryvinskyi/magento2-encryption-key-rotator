<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Infrastructure\Filesystem;

use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Filesystem\AtomicFileWriter;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Filesystem\FileOperations;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Filesystem\FilesystemFailure;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TemporaryDirectory;
use PHPUnit\Framework\TestCase;

/**
 * A write replaces its file atomically and clears away the temporary copies an interrupted write of
 * the same file left, and nothing else.
 */
final class AtomicFileWriterTest extends TestCase
{
    private string $directory;

    protected function setUp(): void
    {
        $this->directory = TemporaryDirectory::create('key-rotator-atomic-writer');
    }

    protected function tearDown(): void
    {
        TemporaryDirectory::remove($this->directory);
    }

    public function testTheFileIsReplacedWithItsModeAndNoTemporaryFileStays(): void
    {
        file_put_contents($this->directory . '/env.php', 'old');

        $this->writer()->write($this->directory . '/env.php', 'new', 0640);

        self::assertSame('new', file_get_contents($this->directory . '/env.php'));
        clearstatcache();
        self::assertSame(0640, fileperms($this->directory . '/env.php') & 0777);
        self::assertSame(['.', '..', 'env.php'], scandir($this->directory));
    }

    public function testTemporaryCopiesAnInterruptedWriteOfTheSameFileLeftAreDeleted(): void
    {
        $stale = [
            '.env.php.key-rotator-' . str_repeat('ab', 12) . '.tmp',
            '.env.php.key-rotator-' . str_repeat('01', 12) . '.tmp',
        ];
        $kept = [
            '.config.php.key-rotator-' . str_repeat('ab', 12) . '.tmp',
            '.env.php.key-rotator-' . str_repeat('ab', 11) . '.tmp',
            '.env.php.' . str_repeat('ab', 6) . '.tmp',
            'env.php.key-rotator-' . str_repeat('ab', 12) . '.tmp',
            '.env.php.key-rotator-' . str_repeat('ab', 12) . '.tmp.bak',
        ];
        foreach ([...$stale, ...$kept] as $name) {
            file_put_contents($this->directory . '/' . $name, "<?php return ['crypt' => ['key' => 'secret']];");
        }
        $directory = '.env.php.key-rotator-' . str_repeat('cd', 12) . '.tmp';
        mkdir($this->directory . '/' . $directory);

        $this->writer()->write($this->directory . '/env.php', 'new', 0600);

        $left = array_values(array_diff(scandir($this->directory) ?: [], ['.', '..']));
        $expected = [...$kept, $directory, 'env.php'];
        sort($left);
        sort($expected);
        self::assertSame($expected, $left);
    }

    public function testAFailedWriteLeavesTheOldFileAndNoTemporaryFile(): void
    {
        mkdir($this->directory . '/env.php');
        file_put_contents($this->directory . '/env.php/inside', 'x');

        try {
            $this->writer()->write($this->directory . '/env.php', 'new', 0600);
            self::fail('A file was renamed over a directory.');
        } catch (FilesystemFailure) {
            $this->addToAssertionCount(1);
        }

        self::assertSame(['.', '..', 'env.php'], scandir($this->directory));
    }

    private function writer(): AtomicFileWriter
    {
        return new AtomicFileWriter(new FileOperations());
    }
}
