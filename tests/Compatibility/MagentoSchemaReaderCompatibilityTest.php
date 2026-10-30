<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Compatibility;

use Hryvinskyi\EncryptionKeyRotator\Tests\Support\MagentoReadableColumns;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Process\Process;

/**
 * Holds the tool's tables to the store's own schema reader, run from the code base MAGENTO_ROOT names
 * with the PHP MAGENTO_PHP names (default `php`). `setup:upgrade` and `setup:db:status` read the
 * definition of every column in the database, the tool's tables included, and one column the reader
 * refuses stops both for the whole store, and with them a deployment.
 */
final class MagentoSchemaReaderCompatibilityTest extends TestCase
{
    private const SCRIPT = __DIR__ . '/bin/magento-schema-reader.php';

    public function testTheStoreReadsEveryColumnDefinitionTheToolsTablesUse(): void
    {
        $columns = [];
        foreach (MagentoReadableColumns::DEFINITIONS as $type => $definitions) {
            foreach ($definitions as $definition) {
                $columns[] = $this->column($type, $definition);
            }
        }

        $results = $this->readWithStore($columns);

        foreach ($columns as $position => $column) {
            self::assertSame(
                ['read' => $column['type']],
                $results[$position],
                sprintf('The store reads %s.', $column['definition']),
            );
        }
    }

    public function testTheStoreRefusesTheEnumColumnRelease101Created(): void
    {
        $results = $this->readWithStore([$this->column('enum', "enum('forward','back')")]);

        self::assertSame(['refused' => 'Cannot process definition to array for type enum'], $results[0]);
    }

    /**
     * A column in the shape the store's DbSchemaReader takes from information_schema.COLUMNS.
     *
     * @return array{name: string, default: null, type: string, nullable: bool, definition: string, extra: string, comment: null, charset: ?string, collation: ?string}
     */
    private function column(string $type, string $definition): array
    {
        $characters = in_array($type, ['char', 'varchar', 'text'], true);

        return [
            'name' => 'column_' . $type,
            'default' => null,
            'type' => $type,
            'nullable' => false,
            'definition' => $definition,
            'extra' => '',
            'comment' => null,
            'charset' => $characters ? 'utf8mb4' : null,
            'collation' => $characters ? 'utf8mb4_general_ci' : null,
        ];
    }

    /**
     * @param list<array<string, mixed>> $columns
     * @return list<array<mixed>>
     */
    private function readWithStore(array $columns): array
    {
        $root = getenv('MAGENTO_ROOT');
        if (!is_string($root) || $root === '') {
            self::fail('MAGENTO_ROOT is not set: point it at an installed store code base to run the compatibility suite.');
        }
        $php = getenv('MAGENTO_PHP');
        $php = is_string($php) && $php !== '' ? $php : 'php';

        $process = new Process(
            [$php, '-d', 'display_errors=stderr', self::SCRIPT],
            null,
            ['MAGENTO_ROOT' => $root],
            json_encode(['columns' => $columns], JSON_THROW_ON_ERROR),
            120,
        );
        $process->run();

        if (!$process->isSuccessful()) {
            self::fail(sprintf(
                "The store's schema reader could not run with MAGENTO_PHP \"%s\" on %s (exit code %s). The PHP must satisfy %s/vendor/composer/platform_check.php.\n%s",
                $php,
                $root,
                var_export($process->getExitCode(), true),
                $root,
                trim($process->getErrorOutput()),
            ));
        }

        $output = json_decode($process->getOutput(), true);
        if (!is_array($output) || !is_array($output['results'] ?? null) || !array_is_list($output['results'])) {
            self::fail('The store script answered no result list: ' . $process->getOutput());
        }
        $results = [];
        foreach ($output['results'] as $result) {
            self::assertIsArray($result);
            $results[] = $result;
        }
        self::assertCount(count($columns), $results);

        return $results;
    }
}
