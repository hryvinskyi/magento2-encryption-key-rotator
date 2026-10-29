<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Support;

use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRingParser;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeyRingFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeySlotFactory;

/**
 * A scratch Magento-like root for the runtime adapters: `app/etc/env.php` holding a key ring and a
 * database password, `pub/` and `var/`. Removed with {@see remove()}.
 */
final class ProbeStoreRoot
{
    private function __construct(
        public readonly string $path,
    ) {}

    public static function create(string $cryptKey, string $dbPassword = 'probe-store-password'): self
    {
        $root = new self(TemporaryDirectory::create('key-rotator-store'));
        foreach (['app/etc', 'pub', 'var'] as $directory) {
            mkdir($root->path . '/' . $directory, 0755, true);
        }
        $root->writeDeploymentConfig($cryptKey, $dbPassword);

        return $root;
    }

    /**
     * Rewrites `app/etc/env.php` with another `crypt/key`, keeping its modification time ahead of the
     * previous one.
     */
    public function writeDeploymentConfig(string $cryptKey, string $dbPassword = 'probe-store-password'): void
    {
        $config = [
            'crypt' => ['key' => $cryptKey],
            'db' => [
                'table_prefix' => '',
                'connection' => ['default' => [
                    'host' => '127.0.0.1',
                    'dbname' => 'store',
                    'username' => 'store',
                    'password' => $dbPassword,
                ]],
            ],
        ];
        $file = $this->deploymentConfigFile();
        file_put_contents($file, '<?php' . "\nreturn " . var_export($config, true) . ";\n");
        clearstatcache(true, $file);
    }

    public function deploymentConfigFile(): string
    {
        return $this->path . '/app/etc/env.php';
    }

    public function remove(): void
    {
        TemporaryDirectory::remove($this->path);
    }

    /**
     * The key ring a `crypt/key` value reads as.
     */
    public static function ring(string $cryptKey): KeyRing
    {
        return (new KeyRingParser(new DirectKeySlotFactory(), new DirectKeyRingFactory()))->parse($cryptKey);
    }
}
