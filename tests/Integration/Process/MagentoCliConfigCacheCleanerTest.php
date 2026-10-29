<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\Process;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\DatabaseSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\MagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Process\MagentoCliConfigCacheCleaner;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Security\PatternSecretRedactor;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectCacheCleanOutcomeFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectProcessFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\FixedMagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\InMemoryDeploymentConfig;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\ProbeStoreRoot;
use PHPUnit\Framework\TestCase;

/**
 * The cleaner runs the store's own `bin/magento cache:clean config` in the store's root; a failure
 * reports the command's last error lines with every secret redacted.
 */
final class MagentoCliConfigCacheCleanerTest extends TestCase
{
    private const PASSWORD = 'cleaner-db-password';

    private ProbeStoreRoot $store;

    protected function setUp(): void
    {
        $this->store = ProbeStoreRoot::create(KeyMaterial::rawKey());
        mkdir($this->store->path . '/bin');
    }

    protected function tearDown(): void
    {
        $this->store->remove();
    }

    public function testACommandThatSucceedsCleansTheCacheFromTheStoreRoot(): void
    {
        $this->fakeMagento(<<<'PHP'
            file_put_contents(__DIR__ . '/../var/calls.log', getcwd() . ' ' . implode(' ', array_slice($argv, 1)));
            echo "Cleaned cache types:\nconfig\n";
            exit(0);
            PHP);

        $outcome = $this->cleaner()->clean();

        self::assertTrue($outcome->cleaned(), $outcome->reason());
        self::assertSame($this->store->path . ' cache:clean config', file_get_contents($this->store->path . '/var/calls.log'));
    }

    public function testAFailingCommandReportsItsLastErrorLinesRedacted(): void
    {
        $ciphertext = '0:3:' . base64_encode(random_bytes(48));
        $this->fakeMagento(sprintf(<<<'PHP'
            $lines = [
                'first line, beyond the last five',
                'second line, beyond the last five',
                'In Mysql.php line 600:',
                'SQLSTATE[HY000] [1045] Access denied (using password: %s)',
                'Cannot decrypt %s',
                str_repeat('word ', 60),
                'cache:clean [--bootstrap BOOTSTRAP] [--] [<types>...]',
            ];
            fwrite(STDERR, implode("\n", $lines) . "\n");
            exit(1);
            PHP, self::PASSWORD, $ciphertext));

        $outcome = $this->cleaner()->clean();

        self::assertFalse($outcome->cleaned());
        $reason = $outcome->reason();
        self::assertStringStartsWith('bin/magento cache:clean config exited with code 1: In Mysql.php line 600:', $reason);
        self::assertStringNotContainsString('beyond the last five', $reason);
        self::assertStringNotContainsString(self::PASSWORD, $reason);
        self::assertStringNotContainsString($ciphertext, $reason);
        self::assertStringContainsString('(using password: [redacted])', $reason);
        self::assertStringContainsString('Cannot decrypt [redacted]', $reason);
        self::assertStringContainsString(' | ' . substr(str_repeat('word ', 60), 0, 200) . '… | ', $reason);
        self::assertStringEndsWith('cache:clean [--bootstrap BOOTSTRAP] [--] [<types>...]', $reason);
    }

    public function testAFailingCommandThatWritesOnlyToItsOutputReportsThat(): void
    {
        $this->fakeMagento(<<<'PHP'
            echo "The store is not installed.\n";
            exit(2);
            PHP);

        $outcome = $this->cleaner()->clean();

        self::assertFalse($outcome->cleaned());
        self::assertSame('bin/magento cache:clean config exited with code 2: The store is not installed.', $outcome->reason());
    }

    private function fakeMagento(string $body): void
    {
        file_put_contents($this->store->path . '/bin/magento', "<?php\n" . $body . "\n");
    }

    private function cleaner(): MagentoCliConfigCacheCleaner
    {
        $config = new InMemoryDeploymentConfig(
            ProbeStoreRoot::ring(KeyMaterial::rawKey()),
            databaseSettings: new DatabaseSettings('db', 3306, null, 'store', 'store', self::PASSWORD, '', ''),
        );

        return new MagentoCliConfigCacheCleaner(
            new FixedMagentoRoot(new MagentoRoot($this->store->path)),
            new DirectProcessFactory(),
            new DirectCacheCleanOutcomeFactory(),
            new PatternSecretRedactor($config),
        );
    }
}
