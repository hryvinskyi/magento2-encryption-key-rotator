<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Infrastructure\Magento;

use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento\LiteralDataInspector;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class LiteralDataInspectorTest extends TestCase
{
    /**
     * @return iterable<string, array{string}>
     */
    public static function literalSources(): iterable
    {
        yield 'short arrays of every scalar' => ["<?php\nreturn [\n    'a' => 'x',\n    'b' => 1,\n    'c' => 2.5,\n    'd' => true,\n    'e' => false,\n    'f' => null,\n    'g' => [\n        'h'\n    ]\n];\n"];
        yield 'long array syntax' => ["<?php return array('a' => array(1, 2), 'b' => \"double quoted\\n\");"];
        yield 'signed numbers' => ['<?php return [-1, +2, -0.5, 1e3];'];
        yield 'words in any case' => ['<?php return [TRUE, False, NULL];'];
        yield 'comments' => ["<?php\n/** The deployment configuration. */\n// a note\n# another\nreturn ['a' => 1]; /* trailing */\n"];
        yield 'a closing tag' => ["<?php return ['a' => 1];\n?>"];
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function sourcesWithExpressions(): iterable
    {
        yield 'a function call' => ["<?php return ['password' => getenv('DB_PASSWORD')];"];
        yield 'a variable' => ['<?php $host = "db"; return ["host" => $host];'];
        yield 'a constant' => ['<?php return ["eol" => PHP_EOL];'];
        yield 'a class constant' => ['<?php return ["mode" => \PDO::ATTR_ERRMODE];'];
        yield 'the directory constant' => ['<?php return ["root" => __DIR__];'];
        yield 'an include' => ["<?php return include 'other.php';"];
        yield 'a require' => ["<?php return require __DIR__ . '/other.php';"];
        yield 'an interpolated string' => ['<?php return ["x" => "{$y}"];'];
        yield 'a heredoc' => ["<?php return ['x' => <<<TXT\nvalue\nTXT];"];
        yield 'a concatenation' => ["<?php return ['x' => 'a' . 'b'];"];
        yield 'a ternary' => ["<?php return ['x' => 1 ? 'a' : 'b'];"];
        yield 'an object' => ['<?php return ["x" => new ArrayObject()];'];
        yield 'output before the tag' => ["\n<?php return [];"];
        yield 'a fully qualified word' => ['<?php return [\true];'];
        yield 'a strict types declaration' => ['<?php declare(strict_types=1); return [];'];
    }

    #[DataProvider('literalSources')]
    public function testLiteralDataIsAccepted(string $source): void
    {
        self::assertTrue((new LiteralDataInspector())->holdsOnlyLiteralData($source));
    }

    #[DataProvider('sourcesWithExpressions')]
    public function testAnythingThatIsNotLiteralDataIsRefused(string $source): void
    {
        self::assertFalse((new LiteralDataInspector())->holdsOnlyLiteralData($source));
    }
}
