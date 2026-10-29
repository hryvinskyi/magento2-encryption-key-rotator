<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\Run;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\KeptKeyRole;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ConflictingRuns;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\KeptMaterialConflict;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunLocked;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunStore;
use Hryvinskyi\EncryptionKeyRotator\Application\Run\CorruptRunFile;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeySlot;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRun;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run\FilesystemRunStore;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\DeploymentConfigServices;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\ScratchMagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TemporaryDirectory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Process\InputStream;
use Symfony\Component\Process\Process;

/**
 * What the run store on disk does beyond the run store contract: the files it leaves, their modes, the
 * lock against another process, and where it roots itself.
 */
final class FilesystemRunStoreTest extends TestCase
{
    private const FIRST = '0123456789abcdef0123456789abcdef';
    private const SECOND = 'fedcba9876543210fedcba9876543210';

    private DeploymentConfigServices $services;
    private string $root;
    private string $state;
    private string $stateParent;

    protected function setUp(): void
    {
        $this->services = DeploymentConfigServices::shared();
        $this->root = ScratchMagentoRoot::create(ScratchMagentoRoot::RETIRED_SLOT_AND_PREFIX);
        mkdir($this->root . '/var', 0755);
        $this->stateParent = TemporaryDirectory::create('key-rotator-state');
        $this->state = $this->stateParent . '/encryption-key-rotation';
        $this->services->pointAtRoot($this->root);
        $this->services->pointAtStateDirectory($this->state);
    }

    protected function tearDown(): void
    {
        TemporaryDirectory::remove($this->root);
        TemporaryDirectory::remove($this->stateParent);
    }

    public function testTheContainerBindsThePortToTheStoreOnDisk(): void
    {
        self::assertInstanceOf(FilesystemRunStore::class, $this->services->get(RunStore::class));
    }

    public function testTheRunDirectoryIsTheOwnersOnlyEvenUnderAPermissiveUmask(): void
    {
        $store = $this->store();
        $id = new RunId(self::FIRST);
        $previous = umask(0);
        try {
            $store->save($this->startedRun(self::FIRST));
            $store->backupDeploymentConfig($id);
            $store->keepKey($id, KeptKeyRole::Added, new KeySlot(2, KeyMaterial::base64Key()));
            $store->keepPlaceholders($id, [new KeySlot(0, KeyMaterial::placeholder())]);
            $store->lock();
            $store->unlock();
        } finally {
            umask($previous);
        }

        $directory = $this->state . '/' . self::FIRST;
        self::assertSame(0711, $this->mode($this->state));
        self::assertSame(0700, $this->mode($directory));
        self::assertSame(
            ['env.php.bak', 'keys.json', 'placeholders.json', 'run.json'],
            $this->sorted(ScratchMagentoRoot::entries($directory)),
            'Only the run files are left; no temporary file stays behind.',
        );
        foreach (ScratchMagentoRoot::entries($directory) as $file) {
            self::assertSame(0600, $this->mode($directory . '/' . $file), $file);
        }
        self::assertSame(0600, $this->mode($this->state . '/.lock'));
    }

    public function testALockHeldByAnotherProcessRefusesTheStore(): void
    {
        $store = $this->store();
        $store->lock();
        $store->unlock();
        $holder = new Process([
            PHP_BINARY,
            '-r',
            '$h = fopen($argv[1], "c"); if (!flock($h, LOCK_EX)) { exit(1); } echo "locked\n"; fgets(STDIN);',
            '--',
            $this->state . '/.lock',
        ]);
        $input = new InputStream();
        $holder->setInput($input);
        $holder->start();
        $holder->waitUntil(static fn(string $type, string $output): bool => str_contains($output, 'locked'));

        try {
            $store->lock();
            self::fail('The store took a lock another process holds.');
        } catch (RunLocked $locked) {
            self::assertStringContainsString($this->state . '/.lock', $locked->getMessage());
        } finally {
            $input->close();
            $holder->wait();
        }

        $store->lock();
        $store->unlock();
    }

    public function testASavedRunIsReadBackByAnotherStoreAndIsTheActiveOne(): void
    {
        $run = $this->startedRun(self::FIRST);
        $this->store()->save($run);

        $other = $this->store();

        self::assertSame($run->snapshot(), $other->get(new RunId(self::FIRST))->snapshot());
        self::assertSame(self::FIRST, $other->active()?->id()->toString());
        self::assertSame(self::FIRST, $other->latest()?->id()->toString());
    }

    public function testTwoUnfinishedRunsOnDiskAreAnErrorNamingBoth(): void
    {
        $store = $this->store();
        $store->save($this->startedRun(self::FIRST));
        $store->save($this->startedRun(self::SECOND));

        $this->expectException(ConflictingRuns::class);
        $this->expectExceptionMessage(self::FIRST . ', ' . self::SECOND);

        $this->store()->active();
    }

    public function testAKeptKeyIsNeverOverwrittenOnDisk(): void
    {
        $store = $this->store();
        $id = new RunId(self::FIRST);
        $kept = KeyMaterial::base64Key();
        $store->keepKey($id, KeptKeyRole::Retired, new KeySlot(1, $kept));
        $keys = $this->state . '/' . self::FIRST . '/keys.json';
        $before = ScratchMagentoRoot::bytes($keys);
        $other = KeyMaterial::base64Key();

        try {
            $this->store()->keepKey($id, KeptKeyRole::Retired, new KeySlot(1, $other));
            self::fail('A kept key was overwritten.');
        } catch (KeptMaterialConflict $conflict) {
            self::assertStringNotContainsString($kept, $conflict->getMessage());
            self::assertStringNotContainsString($other, $conflict->getMessage());
        }

        self::assertSame($before, ScratchMagentoRoot::bytes($keys));
        self::assertSame([$kept], array_map(static fn(KeySlot $s): string => $s->raw(), $this->store()->keptKeys($id, KeptKeyRole::Retired)));
    }

    public function testTheFirstPlaceholdersAreKept(): void
    {
        $store = $this->store();
        $id = new RunId(self::FIRST);
        $first = [new KeySlot(0, KeyMaterial::placeholder()), new KeySlot(1, KeyMaterial::placeholder())];
        $store->keepPlaceholders($id, $first);

        try {
            $this->store()->keepPlaceholders($id, [new KeySlot(0, KeyMaterial::placeholder()), new KeySlot(1, KeyMaterial::placeholder())]);
            self::fail('Kept placeholders were replaced.');
        } catch (KeptMaterialConflict) {
            $this->addToAssertionCount(1);
        }

        self::assertSame(
            array_map(static fn(KeySlot $s): string => $s->raw(), $first),
            array_map(static fn(KeySlot $s): string => $s->raw(), $this->store()->keptPlaceholders($id)),
        );
    }

    public function testTheBackupHoldsTheFileAsItWasWhenTheRunFirstKeptIt(): void
    {
        $store = $this->store();
        $id = new RunId(self::FIRST);
        $file = $this->root . '/app/etc/env.php';
        $original = ScratchMagentoRoot::bytes($file);
        $store->backupDeploymentConfig($id);

        file_put_contents($file, str_replace("'m2_'", "'changed_'", $original));
        $store->backupDeploymentConfig($id);

        self::assertSame($original, ScratchMagentoRoot::bytes($this->state . '/' . self::FIRST . '/env.php.bak'));
    }

    public function testADiscardedRunLeavesNoFileOfItBehind(): void
    {
        $store = $this->store();
        $id = new RunId(self::FIRST);
        $store->save($this->startedRun(self::FIRST));
        $store->backupDeploymentConfig($id);
        $store->keepKey($id, KeptKeyRole::Added, new KeySlot(2, KeyMaterial::base64Key()));
        $store->keepPlaceholders($id, [new KeySlot(0, KeyMaterial::placeholder())]);
        file_put_contents($this->state . '/' . self::FIRST . '/.keys.json.abandoned.tmp', KeyMaterial::base64Key());

        $store->discard($id);

        self::assertDirectoryDoesNotExist($this->state . '/' . self::FIRST);
        self::assertSame([], ScratchMagentoRoot::entries($this->state));
    }

    public function testTheStoreRootsItselfAtTheProvidersDirectoryNotAtTheMagentoRoot(): void
    {
        $store = $this->store();
        $id = new RunId(self::FIRST);
        $store->lock();
        $store->save($this->startedRun(self::FIRST));
        $store->backupDeploymentConfig($id);
        $store->unlock();

        self::assertSame([], ScratchMagentoRoot::entries($this->root . '/var'));
        self::assertSame(['.lock', self::FIRST], $this->sorted(ScratchMagentoRoot::entries($this->state)));
        self::assertFileExists($this->state . '/' . self::FIRST . '/run.json');
    }

    public function testACorruptRunRecordIsReportedWithTheRun(): void
    {
        $store = $this->store();
        $store->save($this->startedRun(self::FIRST));
        file_put_contents($this->state . '/' . self::FIRST . '/run.json', '{"format": 1, "id": ');

        $this->expectException(CorruptRunFile::class);
        $this->expectExceptionMessage(self::FIRST);

        $this->store()->get(new RunId(self::FIRST));
    }

    private function store(): RunStore
    {
        return $this->services->freshRunStore();
    }

    private function startedRun(string $id): RotationRun
    {
        return new RotationRun(new RunId($id), '00000000000000aa', [0], 1, new \DateTimeImmutable('2026-10-29T10:00:00.000000+00:00'));
    }

    private function mode(string $path): int
    {
        clearstatcache(true, $path);

        return fileperms($path) & 0777;
    }

    /**
     * @param list<string> $entries
     *
     * @return list<string>
     */
    private function sorted(array $entries): array
    {
        sort($entries);

        return $entries;
    }
}
