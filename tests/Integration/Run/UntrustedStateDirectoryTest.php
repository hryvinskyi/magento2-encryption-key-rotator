<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\Run;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\KeptKeyRole;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunStore;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeySlot;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRun;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run\UntrustedStateDirectory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\DeploymentConfigServices;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\ScratchMagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TemporaryDirectory;
use PHPUnit\Framework\TestCase;

/**
 * The run store on disk, with the real wiring, refuses a state directory someone else could have
 * changed, before it reads or writes anything there.
 *
 * Files of "another user" are given to a user id the test process is not; the integration
 * containers run as root, which may give a file away.
 */
final class UntrustedStateDirectoryTest extends TestCase
{
    private const RUN = '0123456789abcdef0123456789abcdef';
    private const STRANGER = 4242;

    private DeploymentConfigServices $services;

    private string $root;

    private string $parent;

    private string $state;

    private string $victim;

    protected function setUp(): void
    {
        $this->services = DeploymentConfigServices::shared();
        $this->root = ScratchMagentoRoot::create(ScratchMagentoRoot::RETIRED_SLOT_AND_PREFIX);
        $this->parent = TemporaryDirectory::create('key-rotator-untrusted-state');
        $this->state = $this->parent . '/encryption-key-rotation';
        $this->victim = TemporaryDirectory::create('key-rotator-victim');
        file_put_contents($this->victim . '/precious', 'must survive');
        $this->services->pointAtRoot($this->root);
        $this->services->pointAtStateDirectory($this->state);
    }

    protected function tearDown(): void
    {
        chmod($this->parent, 0700);
        TemporaryDirectory::remove($this->root);
        TemporaryDirectory::remove($this->parent);
        TemporaryDirectory::remove($this->victim);
    }

    public function testATrustedStateDirectoryUnderAStickyParentIsUsed(): void
    {
        chmod($this->parent, 01777);

        $store = $this->store();
        $store->lock();
        $store->save($this->startedRun());
        $store->unlock();

        self::assertSame(self::RUN, $this->store()->active()?->id()->toString());
    }

    public function testAStateDirectoryThatIsASymbolicLinkIsRefusedAndNothingIsWrittenWhereItPoints(): void
    {
        symlink($this->victim, $this->state);

        $this->assertRefused(fn() => $this->store()->lock(), 'is a symbolic link');
        $this->assertRefused(fn() => $this->store()->save($this->startedRun()), 'is a symbolic link');
        $this->assertRefused(fn() => $this->store()->active(), 'is a symbolic link');

        self::assertSame(['.', '..', 'precious'], scandir($this->victim));
    }

    public function testAStateDirectoryItsGroupCanWriteIsRefused(): void
    {
        $this->store()->save($this->startedRun());
        chmod($this->state, 0771);

        $this->assertRefused(fn() => $this->store()->get(new RunId(self::RUN)), '(mode 0771) can be written by its group or by others');
        $this->assertRefused(fn() => $this->store()->lock(), 'Pass --state-dir');
    }

    public function testAParentItsGroupCanWriteWithoutTheStickyBitIsRefusedAndTheMessageSaysWhatToDo(): void
    {
        chmod($this->parent, 0775);

        $refusal = $this->assertRefused(fn() => $this->store()->lock(), 'above the state directory can be written by its group or by others');

        self::assertStringContainsString('Pass --state-dir', $refusal->getMessage());
        self::assertStringContainsString('PHP-FPM can also enter', $refusal->getMessage());
        self::assertDirectoryDoesNotExist($this->state, 'Nothing was created below the refused parent.');
    }

    public function testAStateDirectoryOfAnotherUserIsRefused(): void
    {
        $this->store()->save($this->startedRun());
        $this->giveAway($this->state);

        $this->assertRefused(fn() => $this->store()->active(), sprintf('belongs to user id %d', self::STRANGER));
    }

    public function testARunDirectoryOfAnotherUserIsRefused(): void
    {
        $this->store()->save($this->startedRun());
        $this->giveAway($this->state . '/' . self::RUN);

        $this->assertRefused(fn() => $this->store()->active(), sprintf('belongs to user id %d', self::STRANGER));
        $this->assertRefused(fn() => $this->store()->get(new RunId(self::RUN)), sprintf('belongs to user id %d', self::STRANGER));
        $this->assertRefused(fn() => $this->store()->discard(new RunId(self::RUN)), sprintf('belongs to user id %d', self::STRANGER));
        self::assertFileExists($this->state . '/' . self::RUN . '/run.json');
    }

    public function testKeptKeysOfAnotherUserAreRefused(): void
    {
        $store = $this->store();
        $store->keepKey(new RunId(self::RUN), KeptKeyRole::Added, new KeySlot(2, KeyMaterial::base64Key()));
        $this->giveAway($this->state . '/' . self::RUN . '/keys.json');

        $this->assertRefused(fn() => $this->store()->keptKeys(new RunId(self::RUN), KeptKeyRole::Added), sprintf('belongs to user id %d', self::STRANGER));
    }

    public function testPlantedKeysThatAreASymbolicLinkAreRefused(): void
    {
        $this->store()->save($this->startedRun());
        file_put_contents($this->victim . '/keys.json', '{"added": [], "retired": []}');
        symlink($this->victim . '/keys.json', $this->state . '/' . self::RUN . '/keys.json');

        $this->assertRefused(fn() => $this->store()->keptKeys(new RunId(self::RUN), KeptKeyRole::Retired), 'is a symbolic link');
        $this->assertRefused(
            fn() => $this->store()->keepKey(new RunId(self::RUN), KeptKeyRole::Added, new KeySlot(2, KeyMaterial::base64Key())),
            'is a symbolic link',
        );
        self::assertSame('{"added": [], "retired": []}', file_get_contents($this->victim . '/keys.json'));
    }

    public function testALockFileThatIsASymbolicLinkIsRefusedAndItsTargetIsUntouched(): void
    {
        mkdir($this->state, 0711);
        symlink($this->victim . '/precious', $this->state . '/.lock');

        $this->assertRefused(fn() => $this->store()->lock(), 'is a symbolic link');

        self::assertSame('must survive', file_get_contents($this->victim . '/precious'));
    }

    public function testARunDirectorySwappedForASymbolicLinkIsNeverShreddedThrough(): void
    {
        $store = $this->store();
        $store->save($this->startedRun());
        $store->keepKey(new RunId(self::RUN), KeptKeyRole::Added, new KeySlot(2, KeyMaterial::base64Key()));
        file_put_contents($this->victim . '/run.json', 'a run record elsewhere');
        TemporaryDirectory::remove($this->state . '/' . self::RUN);
        symlink($this->victim, $this->state . '/' . self::RUN);

        $this->assertRefused(fn() => $this->store()->discard(new RunId(self::RUN)), 'is a symbolic link');

        self::assertSame(['.', '..', 'precious', 'run.json'], scandir($this->victim));
        self::assertSame('must survive', file_get_contents($this->victim . '/precious'));
        self::assertSame('a run record elsewhere', file_get_contents($this->victim . '/run.json'));
    }

    /**
     * @param \Closure(): mixed $operation
     */
    private function assertRefused(\Closure $operation, string $reason): UntrustedStateDirectory
    {
        try {
            $operation();
        } catch (UntrustedStateDirectory $refused) {
            self::assertStringContainsString($reason, $refused->getMessage());

            return $refused;
        }

        self::fail(sprintf('The store went on although %s.', $reason));
    }

    private function giveAway(string $path): void
    {
        if (!@chown($path, self::STRANGER)) {
            self::fail(sprintf('Cannot give %s to user id %d: run the integration tests as root, as their containers do.', $path, self::STRANGER));
        }
    }

    private function store(): RunStore
    {
        return $this->services->freshRunStore();
    }

    private function startedRun(): RotationRun
    {
        return new RotationRun(new RunId(self::RUN), '00000000000000aa', [0], 1, new \DateTimeImmutable('2026-10-29T10:00:00.000000+00:00'));
    }
}
