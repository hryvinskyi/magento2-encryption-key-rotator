<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Infrastructure\Run;

use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Filesystem\FileOperations;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Filesystem\FilesystemFailure;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run\RunDirectoryShredder;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run\StateDirectoryTrust;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run\UntrustedStateDirectory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\FixedRuntimeUser;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TemporaryDirectory;
use PHPUnit\Framework\TestCase;

/**
 * Removing a run directory zeroes and deletes the run's own files, and never anything a symbolic link
 * leads to.
 */
final class RunDirectoryShredderTest extends TestCase
{
    private string $state;

    private string $run;

    private string $victim;

    protected function setUp(): void
    {
        $this->state = TemporaryDirectory::create('key-rotator-shredder');
        $this->run = $this->state . '/0123456789abcdef0123456789abcdef';
        $this->victim = $this->state . '/victim';
        mkdir($this->victim, 0700);
        file_put_contents($this->victim . '/keys.json', 'not the run\'s');
        file_put_contents($this->victim . '/run.json', 'not the run\'s either');
    }

    protected function tearDown(): void
    {
        TemporaryDirectory::remove($this->state);
    }

    public function testTheRunsFilesAndDirectoryAreRemoved(): void
    {
        mkdir($this->run, 0700);
        file_put_contents($this->run . '/keys.json', 'key material');
        file_put_contents($this->run . '/run.json', '{}');

        $this->shredder()->destroy($this->run, 'run.json');

        self::assertDirectoryDoesNotExist($this->run);
        $this->assertVictimUntouched();
    }

    public function testARunDirectoryThatIsASymbolicLinkIsRefusedAndWhatItPointsToIsUntouched(): void
    {
        symlink($this->victim, $this->run);

        try {
            $this->shredder()->destroy($this->run, 'run.json');
            self::fail('A symbolic link was shredded through.');
        } catch (UntrustedStateDirectory $untrusted) {
            self::assertStringContainsString('is a symbolic link', $untrusted->getMessage());
        }

        self::assertTrue(is_link($this->run));
        $this->assertVictimUntouched();
    }

    public function testAnEntryThatIsASymbolicLinkIsRefusedAndItsTargetIsUntouched(): void
    {
        mkdir($this->run, 0700);
        file_put_contents($this->run . '/run.json', '{}');
        symlink($this->victim . '/keys.json', $this->run . '/keys.json');

        $this->expectException(UntrustedStateDirectory::class);

        try {
            $this->shredder()->destroy($this->run, 'run.json');
        } finally {
            $this->assertVictimUntouched();
            self::assertFileExists($this->run . '/run.json');
        }
    }

    public function testARunRecordThatIsASymbolicLinkIsRefused(): void
    {
        mkdir($this->run, 0700);
        symlink($this->victim . '/run.json', $this->run . '/run.json');

        $this->expectException(UntrustedStateDirectory::class);

        try {
            $this->shredder()->destroy($this->run, 'run.json');
        } finally {
            $this->assertVictimUntouched();
        }
    }

    public function testARunDirectoryOfAnotherUserIsRefusedBeforeAnythingIsTouched(): void
    {
        mkdir($this->run, 0700);
        file_put_contents($this->run . '/keys.json', 'key material');

        try {
            (new RunDirectoryShredder(new StateDirectoryTrust(new FixedRuntimeUser(posix_geteuid() + 1)), new FileOperations()))
                ->destroy($this->run, 'run.json');
            self::fail('Another user\'s directory was shredded.');
        } catch (UntrustedStateDirectory) {
            self::assertSame('key material', file_get_contents($this->run . '/keys.json'));
        }
    }

    public function testADirectoryInsideTheRunDirectoryStopsTheRemoval(): void
    {
        mkdir($this->run . '/nested', 0700, true);

        $this->expectException(FilesystemFailure::class);
        $this->expectExceptionMessage('holds the directory "nested"');

        $this->shredder()->destroy($this->run, 'run.json');
    }

    public function testAMissingRunDirectoryIsNothingToRemove(): void
    {
        $this->shredder()->destroy($this->run, 'run.json');

        $this->assertVictimUntouched();
    }

    private function assertVictimUntouched(): void
    {
        self::assertSame('not the run\'s', file_get_contents($this->victim . '/keys.json'));
        self::assertSame('not the run\'s either', file_get_contents($this->victim . '/run.json'));
    }

    private function shredder(): RunDirectoryShredder
    {
        return new RunDirectoryShredder(new StateDirectoryTrust(new FixedRuntimeUser(posix_geteuid())), new FileOperations());
    }
}
