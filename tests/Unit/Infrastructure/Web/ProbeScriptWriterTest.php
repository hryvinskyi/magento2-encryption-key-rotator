<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Infrastructure\Web;

use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\ProbeScriptWriter;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TemporaryDirectory;
use PHPUnit\Framework\TestCase;

/**
 * Probe files carry a name the sweep recognises, and the sweep deletes exactly those.
 */
final class ProbeScriptWriterTest extends TestCase
{
    private string $directory;

    protected function setUp(): void
    {
        $this->directory = TemporaryDirectory::create('key-rotator-probe-writer');
    }

    protected function tearDown(): void
    {
        TemporaryDirectory::remove($this->directory);
    }

    public function testAProbeFileIsNamedForTheSweepAndWrittenWithoutATemporaryFileLeft(): void
    {
        $writer = new ProbeScriptWriter();
        $name = $writer->newFileName();

        $writer->write($this->directory . '/' . $name, '<?php echo 1;');

        self::assertMatchesRegularExpression('/^key-rotator-probe-[0-9a-f]{32}\.php$/', $name);
        self::assertNotSame($name, $writer->newFileName());
        self::assertSame(['.', '..', $name], scandir($this->directory));
        clearstatcache();
        self::assertSame(ProbeScriptWriter::MODE, fileperms($this->directory . '/' . $name) & 0777);
    }

    public function testAFileTheSweepWouldNotRecogniseIsNeverWritten(): void
    {
        $this->expectException(\LogicException::class);

        (new ProbeScriptWriter())->write($this->directory . '/probe.php', '<?php');
    }

    public function testTheSweepDeletesStaleProbeFilesAndTheirTemporaryFilesOnly(): void
    {
        $hex = str_repeat('0f', 16);
        foreach (['key-rotator-probe-' . $hex . '.php', '.key-rotator-probe-' . $hex . '.php.tmp', 'index.php', 'key-rotator-probe-' . $hex . '.phtml'] as $name) {
            file_put_contents($this->directory . '/' . $name, '<?php');
        }
        symlink('/etc/hosts', $this->directory . '/key-rotator-probe-' . str_repeat('1e', 16) . '.php');

        self::assertSame([], (new ProbeScriptWriter())->sweep($this->directory));

        self::assertSame(['.', '..', 'index.php', 'key-rotator-probe-' . $hex . '.phtml'], scandir($this->directory));
        self::assertFileExists('/etc/hosts');
    }

    public function testAMissingDirectoryHasNothingToSweep(): void
    {
        self::assertSame([], (new ProbeScriptWriter())->sweep($this->directory . '/missing'));
    }
}
