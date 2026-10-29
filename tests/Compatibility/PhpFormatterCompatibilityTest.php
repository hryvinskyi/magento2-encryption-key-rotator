<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Compatibility;

use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento\DeploymentConfigRenderer;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento\PhpArrayFileLoader;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\DeploymentConfigServices;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\ScratchMagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TemporaryDirectory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Process\Process;

/**
 * Holds the tool's rendering of `app/etc/env.php` to the store's own deployment configuration writer,
 * run from the code base MAGENTO_ROOT names with the PHP MAGENTO_PHP names (default `php`): for the same
 * file, the tool's loader and renderer, as the real container builds them, write exactly the bytes the
 * store's formatter writes.
 */
final class PhpFormatterCompatibilityTest extends TestCase
{
    private const SCRIPT = __DIR__ . '/bin/magento-php-formatter.php';

    private ?string $scratch = null;

    protected function tearDown(): void
    {
        if ($this->scratch !== null) {
            TemporaryDirectory::remove($this->scratch);
        }
    }

    public function testTheDeploymentConfigurationFixtureRendersAsTheStoreRendersIt(): void
    {
        $file = ScratchMagentoRoot::fixture(ScratchMagentoRoot::RETIRED_SLOT_AND_PREFIX);

        self::assertSame($this->renderedByStore($file), $this->renderedByTool($file));
    }

    public function testTheCommittedConfigurationFixtureRendersAsTheStoreRendersIt(): void
    {
        $file = ScratchMagentoRoot::fixture(ScratchMagentoRoot::COMMITTED_WITH_ENCRYPTED_VALUE);

        self::assertSame($this->renderedByStore($file), $this->renderedByTool($file));
    }

    public function testEveryShapeOfValueRendersAsTheStoreRendersIt(): void
    {
        $file = $this->scratchFile([
            'empty' => [],
            'nested_empty' => ['a' => ['b' => []]],
            'list' => ['one', 'two', ['three', []]],
            'list_of_lists' => [[1, 2], [3]],
            'gapped' => [0 => 'a', 2 => 'c'],
            'reordered' => [1 => 'b', 0 => 'a'],
            'negative_key' => [-1 => 'minus one'],
            'numeric_string_key' => ['01' => 'leading zero'],
            'floats' => [2.5, 1.0, -0.5, 1.0E+25, 0.1, 0.30000000000000004],
            'ints' => [0, -7, PHP_INT_MAX],
            'booleans' => [true, false],
            'null' => null,
            'strings' => [
                '',
                "it's",
                'back\\slash',
                "line\nbreak",
                "tab\tand carriage\rreturn",
                "nul \0 byte",
                'Пароль — 密码 — 🔑',
                '1:3:' . base64_encode(random_bytes(48)),
            ],
        ]);

        self::assertSame($this->renderedByStore($file), $this->renderedByTool($file));
    }

    private function renderedByTool(string $file): string
    {
        $services = DeploymentConfigServices::shared();

        return $services->get(DeploymentConfigRenderer::class)->render($services->get(PhpArrayFileLoader::class)->load($file));
    }

    private function renderedByStore(string $file): string
    {
        $root = getenv('MAGENTO_ROOT');
        if (!is_string($root) || $root === '') {
            self::fail('MAGENTO_ROOT is not set: point it at an installed store code base to run the compatibility suite.');
        }
        $php = getenv('MAGENTO_PHP');
        $php = is_string($php) && $php !== '' ? $php : 'php';

        $process = new Process([$php, '-d', 'display_errors=stderr', self::SCRIPT, $file], null, ['MAGENTO_ROOT' => $root], null, 120);
        $process->run();
        if (!$process->isSuccessful()) {
            self::fail(sprintf(
                "The store's formatter could not run with MAGENTO_PHP \"%s\" on %s (exit code %s). The PHP must satisfy %s/vendor/composer/platform_check.php.\n%s",
                $php,
                $root,
                var_export($process->getExitCode(), true),
                $root,
                trim($process->getErrorOutput()),
            ));
        }

        return $process->getOutput();
    }

    /**
     * @param array<mixed> $config
     */
    private function scratchFile(array $config): string
    {
        $this->scratch = TemporaryDirectory::create('key-rotator-formatter');
        $file = $this->scratch . '/config.php';
        file_put_contents($file, "<?php\nreturn " . var_export($config, true) . ";\n");

        return $file;
    }
}
