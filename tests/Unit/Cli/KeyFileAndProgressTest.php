<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Cli;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Cli\OptionRefused;
use Hryvinskyi\EncryptionKeyRotator\Cli\Output\ConsoleProgress;
use Hryvinskyi\EncryptionKeyRotator\Cli\Output\TerminalText;
use Hryvinskyi\EncryptionKeyRotator\Cli\Rotate\KeyFile;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\FixedRuntimeUser;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TemporaryDirectory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Output\ConsoleOutput;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Output\StreamOutput;

/**
 * A key file is read only when it is private to its owner; progress goes to the error output.
 */
final class KeyFileAndProgressTest extends TestCase
{
    private string $directory;

    protected function setUp(): void
    {
        $this->directory = TemporaryDirectory::create('key-rotator-key-file');
    }

    protected function tearDown(): void
    {
        TemporaryDirectory::remove($this->directory);
    }

    public function testAPrivateKeyFileYieldsItsEntryWithoutSurroundingWhitespace(): void
    {
        $key = KeyMaterial::base64Key();
        $file = $this->file("\n  " . $key . "\n", 0600);

        self::assertSame($key, $this->keyFile()->read($file));
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function sharedModes(): iterable
    {
        yield 'world-readable' => [0604];
        yield 'group-readable' => [0640];
        yield 'world-readable and group-readable' => [0644];
        yield 'group-writable' => [0620];
    }

    #[DataProvider('sharedModes')]
    public function testAKeyFileItsGroupOrOthersCanReachIsRefusedWithoutReadingIt(int $mode): void
    {
        $key = KeyMaterial::base64Key();
        $file = $this->file($key, $mode);

        try {
            $this->keyFile()->read($file);
            self::fail('A shared key file was read.');
        } catch (OptionRefused $refused) {
            self::assertStringContainsString(sprintf('%04o', $mode), $refused->getMessage());
            self::assertStringNotContainsString($key, $refused->getMessage());
        }
    }

    public function testAKeyFileOfAnotherUserIsRefusedWithoutReadingIt(): void
    {
        $key = KeyMaterial::base64Key();
        $file = $this->file($key, 0600);
        $owner = fileowner($file);
        self::assertIsInt($owner);

        try {
            (new KeyFile(new FixedRuntimeUser($owner + 1)))->read($file);
            self::fail('A key file of another user was read.');
        } catch (OptionRefused $refused) {
            self::assertStringContainsString(sprintf('belongs to user %d, but the tool runs as user %d', $owner, $owner + 1), $refused->getMessage());
            self::assertStringNotContainsString($key, $refused->getMessage());
        }
    }

    public function testAMissingOrEmptyKeyFileIsRefused(): void
    {
        foreach ([$this->directory . '/missing', $this->file(" \n", 0600)] as $file) {
            try {
                $this->keyFile()->read($file);
                self::fail('A key file without a key was read.');
            } catch (OptionRefused $refused) {
                self::assertStringContainsString('--key-file', $refused->getMessage());
            }
        }
    }

    public function testProgressGoesToTheErrorOutputAndTheCountsOnlyWhenVerbose(): void
    {
        $output = new ConsoleOutput(OutputInterface::VERBOSITY_NORMAL);
        $errors = fopen('php://memory', 'w+');
        self::assertIsResource($errors);
        $output->setErrorOutput(new StreamOutput($errors));
        $progress = new ConsoleProgress(new TerminalText());
        $progress->useOutput($output);

        $progress->step('Scanning');
        $progress->advance(new ColumnRef('core_config_data', 'value'), 10);
        $progress->warn('Cache not cleaned');
        rewind($errors);

        $written = (string) stream_get_contents($errors);
        self::assertStringContainsString('Scanning', $written);
        self::assertStringContainsString('Cache not cleaned', $written);
        self::assertStringNotContainsString('10 more', $written);

        $verbose = new BufferedOutput(OutputInterface::VERBOSITY_VERBOSE);
        $progress->useOutput($verbose);
        $progress->advance(new ColumnRef('core_config_data', 'value'), 10);
        self::assertStringContainsString('core_config_data.value: 10 more', $verbose->fetch());
    }

    public function testProgressBeforeACommandStartedFailsLoudly(): void
    {
        $this->expectException(\LogicException::class);

        (new ConsoleProgress(new TerminalText()))->step('Too early');
    }

    /**
     * The key file reader of a tool running as the user who owns the test's files.
     */
    private function keyFile(): KeyFile
    {
        $uid = fileowner($this->directory);
        self::assertIsInt($uid);

        return new KeyFile(new FixedRuntimeUser($uid));
    }

    private function file(string $content, int $mode): string
    {
        $file = $this->directory . '/' . bin2hex(random_bytes(4)) . '.key';
        file_put_contents($file, $content);
        chmod($file, $mode);

        return $file;
    }
}
