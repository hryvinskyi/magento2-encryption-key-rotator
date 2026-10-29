<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\Magento;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueChange;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueSource;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigUnreadable;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigWriter;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\MagentoRootProvider;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\StaleDeploymentConfig;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Ciphertext;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\CiphertextParser;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRingParser;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Filesystem\AtomicFileWriter;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Filesystem\FileOperations;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento\DeploymentConfigFiles;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento\DeploymentConfigMapper;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento\DeploymentConfigRenderer;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento\EnvPhpRewriter;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento\NestedArray;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento\PhpArrayFileLoader;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\HookedProcessFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\DeploymentConfigServices;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\ScratchMagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TemporaryDirectory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Process\Process;

/**
 * The configuration files of a store on disk, read and written through the adapter the real container
 * builds, on scratch copies of the fixtures.
 */
final class EnvPhpDeploymentConfigTest extends TestCase
{
    private const PAYMENT = ['default', 'payment', 'gateway', 'api_secret'];

    private DeploymentConfigServices $services;

    /**
     * @var list<string>
     */
    private array $scratch = [];

    protected function setUp(): void
    {
        $this->services = DeploymentConfigServices::shared();
    }

    protected function tearDown(): void
    {
        foreach ($this->scratch as $directory) {
            TemporaryDirectory::remove($directory);
        }
    }

    public function testTheRingTheDatabaseSettingsAndTheSystemValuesOfBothFilesAreRead(): void
    {
        $root = $this->root(ScratchMagentoRoot::RETIRED_SLOT_AND_PREFIX, ScratchMagentoRoot::COMMITTED_WITH_ENCRYPTED_VALUE);
        $env = ScratchMagentoRoot::evaluate($root . '/app/etc/env.php');
        $committed = ScratchMagentoRoot::evaluate($root . '/app/etc/config.php');

        $ring = $this->reader()->keyRing();
        $settings = $this->reader()->databaseSettings();

        self::assertSame($this->parse($this->string($env, 'crypt', 'key'))->export(), $ring->export());
        self::assertSame(1, $ring->activeIndex());
        self::assertTrue($ring->slots()[0]->isRetired());
        self::assertSame([], $ring->usableOldIndices());

        self::assertSame('db.internal', $settings->host());
        self::assertSame(3307, $settings->port());
        self::assertNull($settings->socket());
        self::assertSame('store', $settings->dbname());
        self::assertSame('store_user', $settings->user());
        self::assertSame($this->string($env, 'db', 'connection', 'default', 'password'), $settings->password());
        self::assertSame('m2_', $settings->tablePrefix());
        self::assertSame('SET NAMES utf8;', $settings->initStatements());

        self::assertSame(
            [['default/payment/gateway/api_secret', $this->string($env, 'system', ...self::PAYMENT), SystemValueSource::Env]],
            $this->described($this->reader()->systemValues()),
        );
        self::assertSame(
            [['default/carriers/courier/password', $this->string($committed, 'system', 'default', 'carriers', 'courier', 'password'), SystemValueSource::Committed]],
            $this->described($this->reader()->committedSystemValues()),
        );
    }

    public function testAStoreWithoutACommittedConfigurationHasNoCommittedValues(): void
    {
        $this->root(ScratchMagentoRoot::RETIRED_SLOT_AND_PREFIX);

        self::assertSame([], $this->reader()->committedSystemValues());
    }

    public function testTheOwnerIsTheOwnerOfTheFile(): void
    {
        $root = $this->root(ScratchMagentoRoot::RETIRED_SLOT_AND_PREFIX);

        self::assertSame(fileowner($root . '/app/etc/env.php'), $this->reader()->ownerUid());
    }

    public function testAnAppendedRingAndASystemChangeAreWrittenAndEverythingElseStays(): void
    {
        $root = $this->root(ScratchMagentoRoot::RETIRED_SLOT_AND_PREFIX);
        $file = $root . '/app/etc/env.php';
        $before = ScratchMagentoRoot::evaluate($file);
        $ring = $this->reader()->keyRing();
        $appended = $this->parse($ring->export() . "\n" . KeyMaterial::base64Key());
        $old = $this->ciphertextAt($before, self::PAYMENT);
        $new = $this->ciphertext(2, 'payment secret under the new key');

        $this->writer()->write($appended, $ring->fingerprint(), [new SystemValueChange(self::PAYMENT, $old, $new)]);

        $expected = $before;
        self::assertIsArray($expected['crypt']);
        $expected['crypt']['key'] = $appended->export();
        self::assertIsArray($expected['system']);
        self::assertIsArray($expected['system']['default']);
        self::assertIsArray($expected['system']['default']['payment']);
        self::assertIsArray($expected['system']['default']['payment']['gateway']);
        $expected['system']['default']['payment']['gateway']['api_secret'] = $new->toString();
        self::assertSame($expected, ScratchMagentoRoot::evaluate($file));
        self::assertSame($appended->fingerprint(), $this->reader()->keyRing()->fingerprint());
        self::assertSame(['env.php'], ScratchMagentoRoot::entries($root . '/app/etc'), 'No temporary file is left behind.');
    }

    public function testRewritingTheSameRingKeepsTheStoresFormatByteForByte(): void
    {
        $root = $this->root(ScratchMagentoRoot::RETIRED_SLOT_AND_PREFIX);
        $ring = $this->reader()->keyRing();

        $this->writer()->write($ring, $ring->fingerprint(), []);

        self::assertSame(
            ScratchMagentoRoot::bytes(ScratchMagentoRoot::fixture(ScratchMagentoRoot::RETIRED_SLOT_AND_PREFIX)),
            ScratchMagentoRoot::bytes($root . '/app/etc/env.php'),
        );
    }

    public function testCommentsOfTheFileAreLostAsWithTheStoresOwnWriter(): void
    {
        $root = $this->root(ScratchMagentoRoot::RETIRED_SLOT_AND_PREFIX);
        $file = $root . '/app/etc/env.php';
        $this->put($file, str_replace("<?php\nreturn [", "<?php\n// edited by hand\nreturn [", ScratchMagentoRoot::bytes($file)));
        $ring = $this->reader()->keyRing();
        self::assertTrue($this->reader()->holdsOnlyLiteralData());

        $this->writer()->write($ring, $ring->fingerprint(), []);

        self::assertStringNotContainsString('edited by hand', ScratchMagentoRoot::bytes($file));
    }

    public function testTheModeOfTheFileIsKept(): void
    {
        $root = $this->root(ScratchMagentoRoot::RETIRED_SLOT_AND_PREFIX);
        $file = $root . '/app/etc/env.php';
        chmod($file, 0640);
        $ring = $this->reader()->keyRing();

        $this->writer()->write($this->parse($ring->export() . "\n" . KeyMaterial::base64Key()), $ring->fingerprint(), []);

        clearstatcache(true, $file);
        self::assertSame(0640, fileperms($file) & 0777);
    }

    public function testTheOwnerAndGroupOfTheFileAreKept(): void
    {
        $root = $this->root(ScratchMagentoRoot::RETIRED_SLOT_AND_PREFIX);
        $file = $root . '/app/etc/env.php';
        if (posix_geteuid() === 0) {
            // As root the write gives the file back to its owner, so make that owner someone else.
            chown($file, 4242);
            chgrp($file, 4243);
        }
        clearstatcache(true, $file);
        $owner = fileowner($file);
        $group = filegroup($file);
        $ring = $this->reader()->keyRing();

        $this->writer()->write($this->parse($ring->export() . "\n" . KeyMaterial::base64Key()), $ring->fingerprint(), []);

        clearstatcache(true, $file);
        self::assertSame($owner, fileowner($file));
        self::assertSame($group, filegroup($file));
    }

    public function testAStaleSystemChangeLeavesTheFileUntouched(): void
    {
        $root = $this->root(ScratchMagentoRoot::RETIRED_SLOT_AND_PREFIX);
        $file = $root . '/app/etc/env.php';
        $bytes = ScratchMagentoRoot::bytes($file);
        $ring = $this->reader()->keyRing();

        try {
            $this->writer()->write(
                $this->parse($ring->export() . "\n" . KeyMaterial::base64Key()),
                $ring->fingerprint(),
                [new SystemValueChange(self::PAYMENT, $this->ciphertext(1, 'what someone else wrote'), $this->ciphertext(2, 'new'))],
            );
            self::fail('A stale system change was written.');
        } catch (StaleDeploymentConfig $stale) {
            self::assertStringContainsString('system/default/payment/gateway/api_secret', $stale->getMessage());
        }

        self::assertSame($bytes, ScratchMagentoRoot::bytes($file));
        self::assertSame(['env.php'], ScratchMagentoRoot::entries($root . '/app/etc'));
    }

    public function testAStaleRingFingerprintLeavesTheFileUntouched(): void
    {
        $root = $this->root(ScratchMagentoRoot::RETIRED_SLOT_AND_PREFIX);
        $file = $root . '/app/etc/env.php';
        $bytes = ScratchMagentoRoot::bytes($file);
        $ring = $this->reader()->keyRing();
        $other = $this->parse(KeyMaterial::base64Key());

        try {
            $this->writer()->write($this->parse($ring->export() . "\n" . KeyMaterial::base64Key()), $other->fingerprint(), []);
            self::fail('A write expecting another ring was applied.');
        } catch (StaleDeploymentConfig $stale) {
            self::assertStringContainsString($ring->fingerprint(), $stale->getMessage());
            self::assertStringContainsString($other->fingerprint(), $stale->getMessage());
        }

        self::assertSame($bytes, ScratchMagentoRoot::bytes($file));
    }

    public function testAWriteThatDoesNotReadBackAsMeantPutsTheContentFromBeforeBack(): void
    {
        $root = $this->root(ScratchMagentoRoot::RETIRED_SLOT_AND_PREFIX);
        $file = $root . '/app/etc/env.php';
        $before = ScratchMagentoRoot::bytes($file);
        $decoy = $root . '/decoy.php';
        $this->put($decoy, "<?php\nreturn ['crypt' => ['key' => 'not what was written']];\n");
        $ring = $this->reader()->keyRing();
        $rewriter = $this->rewriter(static fn(int $call, mixed $input): mixed => $call === 2 ? $decoy : $input);

        try {
            $rewriter->write($this->parse($ring->export() . "\n" . KeyMaterial::base64Key()), $ring->fingerprint(), []);
            self::fail('A write that read back wrong was accepted.');
        } catch (DeploymentConfigUnreadable $unreadable) {
            self::assertStringContainsString('the content it held before was put back', $unreadable->getMessage());
        }

        self::assertSame($before, ScratchMagentoRoot::bytes($file));
    }

    public function testAFileAnotherWriterReplacedBeforeTheReadBackIsLeftAsThatWriterWroteIt(): void
    {
        $root = $this->root(ScratchMagentoRoot::RETIRED_SLOT_AND_PREFIX);
        $file = $root . '/app/etc/env.php';
        $ring = $this->reader()->keyRing();
        $theirs = (string) preg_replace("/'key' => '[^']*'/", "'key' => '" . KeyMaterial::base64Key() . "'", ScratchMagentoRoot::bytes($file));
        $rewriter = $this->rewriter(function (int $call, mixed $input) use ($file, $theirs): mixed {
            if ($call === 2) {
                $this->put($file, $theirs);
            }

            return $input;
        });

        try {
            $rewriter->write($this->parse($ring->export() . "\n" . KeyMaterial::base64Key()), $ring->fingerprint(), []);
            self::fail('A write another writer overtook was accepted.');
        } catch (StaleDeploymentConfig $stale) {
            self::assertStringContainsString('another writer replaced it', $stale->getMessage());
        }

        self::assertSame($theirs, ScratchMagentoRoot::bytes($file), 'The other writer\'s content is never overwritten with an older copy.');
    }

    public function testASymlinkedFileIsWrittenThroughTheLinkWhichStaysALink(): void
    {
        $root = $this->root(ScratchMagentoRoot::RETIRED_SLOT_AND_PREFIX);
        $shared = TemporaryDirectory::create('key-rotator-shared');
        $this->scratch[] = $shared;
        $link = $root . '/app/etc/env.php';
        rename($link, $shared . '/env.php');
        symlink($shared . '/env.php', $link);
        $ring = $this->reader()->keyRing();
        $appended = $this->parse($ring->export() . "\n" . KeyMaterial::base64Key());

        $this->writer()->write($appended, $ring->fingerprint(), []);

        self::assertTrue(is_link($link));
        self::assertSame($shared . '/env.php', readlink($link));
        $target = ScratchMagentoRoot::evaluate($shared . '/env.php');
        self::assertSame($appended->export(), $this->string($target, 'crypt', 'key'));
        self::assertSame($appended->export(), $this->reader()->keyRing()->export());
        self::assertSame(['env.php'], ScratchMagentoRoot::entries($root . '/app/etc'));
        self::assertSame(['env.php'], ScratchMagentoRoot::entries($shared));
    }

    public function testOnlyAFileOfLiteralDataHoldsOnlyLiteralData(): void
    {
        $this->root(ScratchMagentoRoot::RETIRED_SLOT_AND_PREFIX);
        self::assertTrue($this->reader()->holdsOnlyLiteralData());

        $this->root(ScratchMagentoRoot::WITH_GETENV);
        self::assertFalse($this->reader()->holdsOnlyLiteralData());
    }

    public function testTheFileIsWritableOnlyWhenTheFileAndItsDirectoryBothAre(): void
    {
        $root = $this->root(ScratchMagentoRoot::RETIRED_SLOT_AND_PREFIX);
        chmod($root, 0755);
        chmod($root . '/app', 0755);
        $directory = $root . '/app/etc';
        $file = $directory . '/env.php';

        $writable = function (int $fileMode, int $directoryMode) use ($root, $file, $directory): bool {
            chmod($file, $fileMode);
            chmod($directory, $directoryMode);

            return $this->writableUnprivileged($root);
        };

        try {
            self::assertTrue($writable(0666, 0777));
            self::assertFalse($writable(0444, 0777), 'A read-only file cannot be replaced.');
            self::assertFalse($writable(0666, 0555), 'A file in a read-only directory cannot be replaced by a rename.');
        } finally {
            chmod($directory, 0755);
            chmod($file, 0644);
        }
    }

    public function testASymlinkedFileIsWritableByTheDirectoryOfTheFileItPointsTo(): void
    {
        $root = $this->root(ScratchMagentoRoot::RETIRED_SLOT_AND_PREFIX);
        $shared = TemporaryDirectory::create('key-rotator-shared-etc');
        $this->scratch[] = $shared;
        chmod($root, 0755);
        chmod($root . '/app', 0755);
        chmod($shared, 0755);
        rename($root . '/app/etc/env.php', $shared . '/env.php');
        symlink($shared . '/env.php', $root . '/app/etc/env.php');
        chmod($shared . '/env.php', 0666);

        try {
            chmod($root . '/app/etc', 0777);
            chmod($shared, 0555);
            self::assertFalse($this->writableUnprivileged($root), 'The directory of the real file decides, not the link\'s.');
            chmod($shared, 0777);
            chmod($root . '/app/etc', 0555);
            self::assertTrue($this->writableUnprivileged($root));
        } finally {
            chmod($root . '/app/etc', 0755);
            chmod($shared, 0755);
        }
    }

    public function testTheSecretStringsAreTheLongStringsUnderNamesThatMarkThemSecret(): void
    {
        $root = $this->root(ScratchMagentoRoot::RETIRED_SLOT_AND_PREFIX);
        $env = ScratchMagentoRoot::evaluate($root . '/app/etc/env.php');

        self::assertSame(
            [
                $this->string($env, 'crypt', 'key'),
                $this->string($env, 'crypt', 'invalidated_key'),
                $this->string($env, 'db', 'connection', 'default', 'password'),
                $this->string($env, 'system', 'default', 'payment', 'gateway', 'api_secret'),
            ],
            $this->reader()->secretStrings(),
        );
    }

    public function testAFileThatReturnsNoArrayFailsClearly(): void
    {
        $root = $this->root(ScratchMagentoRoot::RETURNING_NON_ARRAY);

        $this->expectException(DeploymentConfigUnreadable::class);
        $this->expectExceptionMessage($root . '/app/etc/env.php does not return an array.');

        $this->reader()->keyRing();
    }

    public function testAFileThatDoesNotParseFailsWithoutItsContent(): void
    {
        $root = $this->root(ScratchMagentoRoot::RETIRED_SLOT_AND_PREFIX);
        $file = $root . '/app/etc/env.php';
        $this->put($file, "<?php\nreturn ['db' => ['password' => 'Secret-In-A-Broken-File'");

        try {
            $this->reader()->keyRing();
            self::fail('A file that does not parse was read.');
        } catch (DeploymentConfigUnreadable $unreadable) {
            self::assertStringContainsString($file, $unreadable->getMessage());
            self::assertStringNotContainsString('Secret-In-A-Broken-File', $unreadable->getMessage());
        }
    }

    public function testTheFileIsReadAsItIsNowOnEveryCall(): void
    {
        $root = $this->root(ScratchMagentoRoot::RETIRED_SLOT_AND_PREFIX);
        $first = $this->reader()->keyRing();
        $replacement = KeyMaterial::base64Key();
        $file = $root . '/app/etc/env.php';
        $this->put($file, (string) preg_replace("/'key' => '[^']*'/", "'key' => '" . $replacement . "'", ScratchMagentoRoot::bytes($file)));

        self::assertNotSame($first->fingerprint(), $this->reader()->keyRing()->fingerprint());
        self::assertSame($replacement, $this->reader()->keyRing()->export());
    }

    private function root(string $envFixture, ?string $committedFixture = null): string
    {
        $root = ScratchMagentoRoot::create($envFixture, $committedFixture);
        $this->scratch[] = $root;
        $this->services->pointAtRoot($root);

        return $root;
    }

    /**
     * Whether the reader finds the root's deployment configuration writable, asked in this process, or,
     * when the tests run as root (for whom every file is writable whatever its mode), in a PHP process
     * running as an unprivileged user.
     */
    private function writableUnprivileged(string $root): bool
    {
        if (posix_geteuid() !== 0) {
            return $this->reader()->isWritable();
        }
        $process = new Process([
            'setpriv', '--reuid=65534', '--regid=65534', '--clear-groups',
            PHP_BINARY, __DIR__ . '/bin/deployment-config-writable.php', $root,
        ]);
        $process->run();
        self::assertTrue($process->isSuccessful(), $process->getErrorOutput());

        return match (trim($process->getOutput())) {
            'true' => true,
            'false' => false,
            default => throw new \LogicException(sprintf('The writability check printed "%s".', $process->getOutput())),
        };
    }

    /**
     * The rewriter with the real collaborators, except that every evaluation of a file first passes
     * through the hook, which may play another writer or swap the file the evaluation reads.
     *
     * @param \Closure(int, mixed): mixed $beforeEachLoad gets the evaluation's number (from 1) and the file it reads
     */
    private function rewriter(\Closure $beforeEachLoad): EnvPhpRewriter
    {
        $files = new DeploymentConfigFiles(
            $this->services->get(MagentoRootProvider::class),
            new PhpArrayFileLoader(new HookedProcessFactory($beforeEachLoad)),
            $this->services->get(FileOperations::class),
        );

        return new EnvPhpRewriter(
            $files,
            $this->services->get(DeploymentConfigMapper::class),
            $this->services->get(NestedArray::class),
            $this->services->get(DeploymentConfigRenderer::class),
            $this->services->get(AtomicFileWriter::class),
        );
    }

    private function reader(): DeploymentConfigReader
    {
        return $this->services->get(DeploymentConfigReader::class);
    }

    private function writer(): DeploymentConfigWriter
    {
        return $this->services->get(DeploymentConfigWriter::class);
    }

    private function parse(string $cryptKey): KeyRing
    {
        return $this->services->get(KeyRingParser::class)->parse($cryptKey);
    }

    /**
     * @param array<mixed> $config
     * @param list<string> $path
     */
    private function ciphertextAt(array $config, array $path): Ciphertext
    {
        return $this->services->get(CiphertextParser::class)->parse($this->string($config, 'system', ...$path))
            ?? throw new \LogicException('The fixture holds a ciphertext there.');
    }

    private function ciphertext(int $keyIndex, string $seed): Ciphertext
    {
        return new Ciphertext($keyIndex, 3, base64_encode(str_pad($seed, 48, '.')));
    }

    /**
     * @param array<mixed> $config
     */
    private function string(array $config, string ...$path): string
    {
        $node = $config;
        foreach ($path as $key) {
            self::assertIsArray($node);
            self::assertArrayHasKey($key, $node);
            $node = $node[$key];
        }
        self::assertIsString($node);

        return $node;
    }

    /**
     * @param list<SystemValue> $values
     *
     * @return list<array{string, string, SystemValueSource}>
     */
    private function described(array $values): array
    {
        return array_map(static fn(SystemValue $v): array => [$v->pathString(), $v->ciphertext()->toString(), $v->source()], $values);
    }

    private function put(string $file, string $bytes): void
    {
        if (file_put_contents($file, $bytes) !== strlen($bytes)) {
            throw new \RuntimeException(sprintf('Cannot write "%s".', $file));
        }
    }
}
