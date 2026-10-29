<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Domain\Crypto;

use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Plaintext;
use PHPUnit\Framework\TestCase;

final class PlaintextTest extends TestCase
{
    public function testThePlaintextKeepsEveryByte(): void
    {
        $bytes = "  leading and trailing\n\t\x00 ünïcødé ";

        self::assertSame($bytes, (new Plaintext($bytes))->bytes());
    }

    public function testPlaintextsAreEqualOnlyWhenTheirBytesAre(): void
    {
        $plaintext = new Plaintext('secret value');

        self::assertTrue($plaintext->equals(new Plaintext('secret value')));
        self::assertFalse($plaintext->equals(new Plaintext('secret value ')));
        self::assertFalse($plaintext->equals(new Plaintext('')));
    }

    public function testDumpingAPlaintextNeverShowsItsBytes(): void
    {
        $secret = 'card-token-' . bin2hex(random_bytes(8));
        $plaintext = new Plaintext($secret);

        ob_start();
        var_dump($plaintext);
        $dumped = (string) ob_get_clean();
        $printed = print_r($plaintext, true);

        foreach ([$dumped, $printed] as $output) {
            self::assertStringNotContainsString($secret, $output);
            self::assertStringContainsString('[redacted]', $output);
        }
    }

    public function testAPlaintextIsNeverSerialised(): void
    {
        $this->expectException(\LogicException::class);

        serialize(new Plaintext('secret value'));
    }

    public function testAPlaintextIsNeverUnserialised(): void
    {
        $forged = sprintf('O:%d:"%s":0:{}', strlen(Plaintext::class), Plaintext::class);

        $this->expectException(\LogicException::class);

        unserialize($forged);
    }
}
