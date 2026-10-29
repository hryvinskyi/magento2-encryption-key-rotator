<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento;

/**
 * Renders a configuration array as the PHP file the store itself writes, byte for byte: `<?php`, a
 * newline, `return ` and the array in short syntax, four spaces of indentation per level, the elements
 * of a list without their keys, scalars and keys as `var_export()` writes them, `null` in lower case,
 * no comma after the last element, `;` and a trailing newline.
 *
 * The store's quirks are kept so a file the tool rewrites differs from the store's own output only in
 * the values the tool changed: an empty array is written as `[`, an empty line and `]`, with the
 * closing bracket indented one level less than the elements of a non-empty array at that depth would be.
 *
 * Comments are not part of an array, so a rendered file has none.
 */
final class DeploymentConfigRenderer
{
    private const INDENT = '    ';

    /**
     * @param array<mixed> $config the array the file returns: nested arrays of strings, integers, floats,
     *                             booleans and nulls
     *
     * @throws \InvalidArgumentException when the array holds anything else, such as an object
     */
    public function render(array $config): string
    {
        return "<?php\nreturn " . $this->export($config, 1) . ";\n";
    }

    private function export(mixed $value, int $depth): string
    {
        if ($value === null) {
            return 'null';
        }
        if (is_scalar($value)) {
            return var_export($value, true);
        }
        if (!is_array($value)) {
            throw new \InvalidArgumentException(sprintf('A configuration file holds only arrays and scalars, not %s.', get_debug_type($value)));
        }

        $isList = array_keys($value) === range(0, count($value) - 1);
        $elements = [];
        foreach ($value as $key => $element) {
            $elements[] = str_repeat(self::INDENT, $depth)
                . ($isList ? '' : var_export($key, true) . ' => ')
                . $this->export($element, $depth + 1);
        }

        return sprintf("[\n%s\n%s]", implode(",\n", $elements), str_repeat(self::INDENT, $depth - 1));
    }
}
