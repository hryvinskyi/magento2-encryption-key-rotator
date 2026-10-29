<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Infrastructure\Magento;

use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento\DeploymentConfigRenderer;
use PHPUnit\Framework\TestCase;

/**
 * The renderer's output, shape by shape. That it equals the store's own writer for the same array is
 * held by the compatibility suite against the store's code.
 */
final class DeploymentConfigRendererTest extends TestCase
{
    public function testMapsAndListsAreWrittenInShortSyntaxWithFourSpaces(): void
    {
        $rendered = (new DeploymentConfigRenderer())->render([
            'db' => ['table_prefix' => 'm2_', 'driver_options' => [1014 => false]],
            'domains' => ['a.test', 'b.test'],
            'timeout' => 2.5,
            'whole' => 1.0,
            'salt' => null,
            'quote' => "it's a back\\slash",
        ]);

        self::assertSame(
            "<?php\nreturn [\n"
            . "    'db' => [\n"
            . "        'table_prefix' => 'm2_',\n"
            . "        'driver_options' => [\n"
            . "            1014 => false\n"
            . "        ]\n"
            . "    ],\n"
            . "    'domains' => [\n"
            . "        'a.test',\n"
            . "        'b.test'\n"
            . "    ],\n"
            . "    'timeout' => 2.5,\n"
            . "    'whole' => 1.0,\n"
            . "    'salt' => null,\n"
            . "    'quote' => 'it\\'s a back\\\\slash'\n"
            . "];\n",
            $rendered,
        );
    }

    public function testAnEmptyArrayKeepsTheEmptyLineOfTheStoresWriter(): void
    {
        self::assertSame(
            "<?php\nreturn [\n    'dev' => [\n        'restrict' => [\n\n        ]\n    ]\n];\n",
            (new DeploymentConfigRenderer())->render(['dev' => ['restrict' => []]]),
        );
    }

    public function testAListThatSkipsAnIndexKeepsItsKeys(): void
    {
        self::assertSame(
            "<?php\nreturn [\n    1 => 'b',\n    0 => 'a'\n];\n",
            (new DeploymentConfigRenderer())->render([1 => 'b', 0 => 'a']),
        );
    }

    public function testAnObjectIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        (new DeploymentConfigRenderer())->render(['x' => new \ArrayObject()]);
    }
}
