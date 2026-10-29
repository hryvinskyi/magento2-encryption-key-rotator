<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\DatabaseSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\InvalidValue;
use PHPUnit\Framework\TestCase;

final class DatabaseSettingsTest extends TestCase
{
    private const PASSWORD = 'Password-That-Must-Not-Leak-7f3a';

    public function testADumpNeverShowsThePassword(): void
    {
        $settings = new DatabaseSettings('db', 3306, null, 'store', 'store', self::PASSWORD, 'm2_', 'SET NAMES utf8;');

        self::assertStringNotContainsString(self::PASSWORD, print_r($settings, true));
        self::assertStringNotContainsString(self::PASSWORD, var_export($settings->__debugInfo(), true));
        self::assertSame(self::PASSWORD, $settings->password());
        self::assertSame('m2_', $settings->tablePrefix());
    }

    public function testSettingsAreNeverSerialised(): void
    {
        $this->expectException(\LogicException::class);

        serialize(new DatabaseSettings('db', null, null, 'store', 'store', self::PASSWORD, '', ''));
    }

    public function testASocketReplacesTheHost(): void
    {
        self::assertSame('/run/mysqld.sock', (new DatabaseSettings('', null, '/run/mysqld.sock', 'store', 'store', '', '', ''))->socket());
    }

    public function testADatabaseIsNamed(): void
    {
        $this->expectException(InvalidValue::class);

        new DatabaseSettings('db', null, null, '', 'store', '', '', '');
    }

    public function testAPortLiesInRange(): void
    {
        $this->expectException(InvalidValue::class);

        new DatabaseSettings('db', 70000, null, 'store', 'store', '', '', '');
    }
}
