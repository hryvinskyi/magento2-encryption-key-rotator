<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Infrastructure\Runtime;

use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Runtime\IdCommandUserId;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Runtime\PosixRuntimeUser;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Runtime\UserIdUnavailable;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectProcessFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TemporaryDirectory;
use PHPUnit\Framework\TestCase;

/**
 * The runtime user is the test process's own effective user, through the POSIX functions and through
 * `id -u` alike; an `id` that prints no user id is an error, never a guess.
 */
final class PosixRuntimeUserTest extends TestCase
{
    public function testTheRuntimeUserIsTheProcesssEffectiveUser(): void
    {
        $user = new PosixRuntimeUser(new IdCommandUserId(new DirectProcessFactory()));

        self::assertSame($this->ownEffectiveUid(), $user->effectiveUid());
    }

    public function testIdReportsTheSameEffectiveUser(): void
    {
        self::assertSame($this->ownEffectiveUid(), (new IdCommandUserId(new DirectProcessFactory()))->effectiveUid());
    }

    public function testAnIdThatPrintsNoUserIdIsAnError(): void
    {
        $bin = TemporaryDirectory::create('key-rotator-id');
        try {
            file_put_contents($bin . '/id', "#!/bin/sh\necho nobody\n");
            chmod($bin . '/id', 0755);

            $this->expectException(UserIdUnavailable::class);
            (new IdCommandUserId(new DirectProcessFactory(), $bin . '/id'))->effectiveUid();
        } finally {
            TemporaryDirectory::remove($bin);
        }
    }

    public function testAMissingIdIsAnError(): void
    {
        $this->expectException(UserIdUnavailable::class);

        (new IdCommandUserId(new DirectProcessFactory(), '/nonexistent/id'))->effectiveUid();
    }

    private function ownEffectiveUid(): int
    {
        $output = shell_exec('id -u');
        self::assertIsString($output);

        return (int) trim($output);
    }
}
