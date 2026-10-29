<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Infrastructure\Run;

use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run\StateDirectoryTrust;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run\UntrustedStateDirectory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\FixedRuntimeUser;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TemporaryDirectory;
use PHPUnit\Framework\TestCase;

/**
 * The state directory and what lies below it are used only when nobody but the tool's user can have
 * put or changed anything there.
 */
final class StateDirectoryTrustTest extends TestCase
{
    private string $parent;

    private string $state;

    protected function setUp(): void
    {
        $this->parent = TemporaryDirectory::create('key-rotator-trust');
        $this->state = $this->parent . '/state';
    }

    protected function tearDown(): void
    {
        chmod($this->parent, 0700);
        TemporaryDirectory::remove($this->parent);
    }

    public function testAStateDirectoryOfTheToolsUserThatOnlyItCanWriteIsTrusted(): void
    {
        $this->trust()->verifyStateDirectory($this->state);
        mkdir($this->state, 0711);
        $this->trust()->verifyStateDirectory($this->state);
        mkdir($this->state . '/run', 0700);
        touch($this->state . '/run/run.json');

        $this->trust()->verifyDirectory($this->state . '/run');
        $this->trust()->verifyFile($this->state . '/run/run.json');
        $this->trust()->verifyDirectory($this->state . '/missing');
        $this->trust()->verifyFile($this->state . '/missing.json');
        $this->addToAssertionCount(1);
    }

    public function testAMissingStateDirectoryIsJudgedByTheNearestDirectoryThatExists(): void
    {
        chmod($this->parent, 0777);

        $this->expectException(UntrustedStateDirectory::class);
        $this->expectExceptionMessage($this->parent . ' (mode 0777) above the state directory');

        $this->trust()->verifyStateDirectory($this->parent . '/not/yet/state');
    }

    public function testAStickyParentOthersCanWriteIsTrusted(): void
    {
        chmod($this->parent, 01777);
        mkdir($this->state, 0711);

        $this->trust()->verifyStateDirectory($this->state);
        $this->addToAssertionCount(1);
    }

    public function testASymbolicLinkAsTheStateDirectoryIsRefused(): void
    {
        mkdir($this->parent . '/real', 0711);
        symlink($this->parent . '/real', $this->state);

        $this->expectException(UntrustedStateDirectory::class);
        $this->expectExceptionMessage('is a symbolic link');

        $this->trust()->verifyStateDirectory($this->state);
    }

    public function testAStateDirectoryItsGroupCanWriteIsRefusedAndTheMessageSaysWhatToDo(): void
    {
        mkdir($this->state);
        chmod($this->state, 0770);

        try {
            $this->trust()->verifyStateDirectory($this->state);
            self::fail('A group-writable state directory was trusted.');
        } catch (UntrustedStateDirectory $untrusted) {
            self::assertStringContainsString('(mode 0770) can be written by its group or by others', $untrusted->getMessage());
            self::assertStringContainsString('Pass --state-dir', $untrusted->getMessage());
            self::assertStringContainsString('outside var/', $untrusted->getMessage());
        }
    }

    public function testAStateDirectoryOfAnotherUserIsRefused(): void
    {
        mkdir($this->state, 0711);

        $this->expectException(UntrustedStateDirectory::class);
        $this->expectExceptionMessageMatches('/belongs to user id \d+/');

        $this->trust(self::otherUser())->verifyStateDirectory($this->state);
    }

    public function testAnEntryOfAnotherUserIsRefused(): void
    {
        mkdir($this->state, 0711);
        touch($this->state . '/keys.json');
        $owner = fileowner($this->state . '/keys.json');

        $this->expectException(UntrustedStateDirectory::class);
        $this->expectExceptionMessage(sprintf('belongs to user id %d, not to user id %d', $owner, self::otherUser()));

        $this->trust(self::otherUser())->verifyFile($this->state . '/keys.json');
    }

    public function testASymbolicLinkAmongTheEntriesIsRefusedWhereverItPoints(): void
    {
        mkdir($this->state, 0711);
        mkdir($this->parent . '/victim', 0700);
        symlink($this->parent . '/victim', $this->state . '/0123456789abcdef0123456789abcdef');
        symlink($this->parent . '/victim/file', $this->state . '/.lock');

        foreach ([
            fn() => $this->trust()->verifyDirectory($this->state . '/0123456789abcdef0123456789abcdef'),
            fn() => $this->trust()->verifyFile($this->state . '/.lock'),
        ] as $check) {
            try {
                $check();
                self::fail('A symbolic link was trusted.');
            } catch (UntrustedStateDirectory $untrusted) {
                self::assertStringContainsString('is a symbolic link', $untrusted->getMessage());
            }
        }
    }

    public function testAFileWhereADirectoryBelongsIsRefused(): void
    {
        mkdir($this->state, 0711);
        touch($this->state . '/probe');

        $this->expectException(UntrustedStateDirectory::class);
        $this->expectExceptionMessage('is not a directory');

        $this->trust()->verifyDirectory($this->state . '/probe');
    }

    public function testADirectoryBelowTheStateDirectoryOthersCanWriteIsRefused(): void
    {
        mkdir($this->state, 0711);
        mkdir($this->state . '/probe');
        chmod($this->state . '/probe', 0733);

        $this->expectException(UntrustedStateDirectory::class);
        $this->expectExceptionMessage('(mode 0733) can be written by its group or by others');

        $this->trust()->verifyDirectory($this->state . '/probe');
    }

    public function testAParentOfAnotherUserWhoIsNotRootIsRefused(): void
    {
        // Only root can give the directory away; any other user is shown a parent it does not own.
        $runsAsRoot = posix_geteuid() === 0;
        if ($runsAsRoot) {
            chown($this->parent, self::otherUser());
        }

        $this->expectException(UntrustedStateDirectory::class);
        $this->expectExceptionMessage('above the state directory belongs to user id');

        $this->trust($runsAsRoot ? null : self::otherUser())->verifyStateDirectory($this->state);
    }

    public function testAFileSwappedAfterItWasOpenedIsRefused(): void
    {
        mkdir($this->state, 0711);
        file_put_contents($this->state . '/.lock', '');
        $handle = fopen($this->state . '/.lock', 'rb');
        self::assertIsResource($handle);
        file_put_contents($this->state . '/other', '');
        rename($this->state . '/other', $this->state . '/.lock');

        try {
            $this->expectException(UntrustedStateDirectory::class);
            $this->expectExceptionMessage('was replaced while the tool opened it');

            $this->trust()->verifyOpenedFile($this->state . '/.lock', $handle);
        } finally {
            fclose($handle);
        }
    }

    public function testADirectoryReplacedAfterItWasFoundIsRefused(): void
    {
        mkdir($this->state, 0711);
        mkdir($this->state . '/run', 0700);
        $identity = $this->trust()->verifiedDirectory($this->state . '/run');
        self::assertNotNull($identity);
        $this->trust()->verifySameDirectory($this->state . '/run', $identity);
        rename($this->state . '/run', $this->state . '/moved');
        mkdir($this->state . '/run', 0700);

        $this->expectException(UntrustedStateDirectory::class);
        $this->expectExceptionMessage('was replaced while the tool was removing it');

        $this->trust()->verifySameDirectory($this->state . '/run', $identity);
    }

    private function trust(?int $uid = null): StateDirectoryTrust
    {
        return new StateDirectoryTrust(new FixedRuntimeUser($uid ?? posix_geteuid()));
    }

    /**
     * A user id that owns nothing here and is not root.
     */
    private static function otherUser(): int
    {
        return posix_geteuid() === 4242 ? 4343 : 4242;
    }
}
