<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Support;

/**
 * Reads into nested arrays a test did not build itself (decoded JSON, an evaluated configuration file),
 * failing with the path when a level is missing or has another type.
 */
final class Nested
{
    /**
     * @param array<mixed> $data
     */
    public static function value(array $data, string|int ...$path): mixed
    {
        $current = $data;
        foreach ($path as $key) {
            if (!is_array($current) || !array_key_exists($key, $current)) {
                throw new \UnexpectedValueException(sprintf('Nothing at "%s".', implode('/', $path)));
            }
            $current = $current[$key];
        }

        return $current;
    }

    /**
     * @param array<mixed> $data
     *
     * @return array<mixed>
     */
    public static function array(array $data, string|int ...$path): array
    {
        $value = self::value($data, ...$path);

        return is_array($value) ? $value : throw new \UnexpectedValueException(sprintf('"%s" is no array.', implode('/', $path)));
    }

    /**
     * @param array<mixed> $data
     */
    public static function string(array $data, string|int ...$path): string
    {
        $value = self::value($data, ...$path);

        return is_string($value) ? $value : throw new \UnexpectedValueException(sprintf('"%s" is no string.', implode('/', $path)));
    }

    /**
     * @return array<mixed>
     */
    public static function json(string $json): array
    {
        $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

        return is_array($data) ? $data : throw new \UnexpectedValueException('The JSON is no object.');
    }
}
