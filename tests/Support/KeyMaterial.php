<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Support;

/**
 * Fresh random ring entries for tests: every test makes its own keys, none is copied from a store.
 */
final class KeyMaterial
{
    private const ALPHANUMERIC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

    /**
     * A 32-character entry that is its own key bytes.
     */
    public static function rawKey(): string
    {
        return self::alphanumeric(32);
    }

    /**
     * A `base64` entry standing for 32 random bytes.
     */
    public static function base64Key(): string
    {
        return 'base64' . base64_encode(random_bytes(32));
    }

    /**
     * The placeholder of a retired slot: `invalid` and 25 random alphanumeric characters.
     */
    public static function placeholder(): string
    {
        return 'invalid' . self::alphanumeric(25);
    }

    private static function alphanumeric(int $length): string
    {
        $value = '';
        for ($i = 0; $i < $length; $i++) {
            $value .= self::ALPHANUMERIC[random_int(0, strlen(self::ALPHANUMERIC) - 1)];
        }

        return $value;
    }
}
