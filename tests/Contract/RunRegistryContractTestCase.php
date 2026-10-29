<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Contract;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunClaimedElsewhere;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunRegistry;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use PHPUnit\Framework\TestCase;

/**
 * What every implementation of {@see RunRegistry} must do, so the in-memory double the use case tests
 * run against and the store's table behave alike: one claim at most, kept by its run until that run
 * releases it, and refused to every other run with the holder and its state directory named.
 *
 * A subclass for the in-memory double lives under `tests/Contract/`; one for an adapter that needs a
 * database lives under `tests/Integration/Contract/`.
 */
abstract class RunRegistryContractTestCase extends TestCase
{
    private const RUN = '0000000000000000000000000000000a';
    private const OTHER_RUN = '0000000000000000000000000000000b';
    private const STATE_DIRECTORY = '/var/www/store/var/encryption-key-rotation';
    private const OTHER_STATE_DIRECTORY = '/srv/shared/rotation';

    /**
     * The registry under test, over a store that holds no claim yet.
     */
    abstract protected function registry(): RunRegistry;

    /**
     * A second handle onto the same store, as another process from another state directory holds.
     */
    abstract protected function otherProcess(): RunRegistry;

    public function testAStoreWithoutAClaimNamesNoRun(): void
    {
        self::assertNull($this->registry()->claimed());
    }

    public function testAClaimNamesItsRunAndItsStateDirectory(): void
    {
        $this->registry()->claim(new RunId(self::RUN), self::STATE_DIRECTORY);

        $expected = ['run_id' => self::RUN, 'state_directory' => self::STATE_DIRECTORY];
        self::assertSame($expected, $this->registry()->claimed());
        self::assertSame($expected, $this->otherProcess()->claimed());
    }

    public function testClaimingAgainForTheSameRunChangesNothing(): void
    {
        $this->registry()->claim(new RunId(self::RUN), self::STATE_DIRECTORY);

        $this->otherProcess()->claim(new RunId(self::RUN), self::STATE_DIRECTORY);

        self::assertSame(['run_id' => self::RUN, 'state_directory' => self::STATE_DIRECTORY], $this->registry()->claimed());
    }

    public function testAnotherRunIsRefusedWithTheHolderAndItsStateDirectoryNamed(): void
    {
        $this->registry()->claim(new RunId(self::RUN), self::STATE_DIRECTORY);

        try {
            $this->otherProcess()->claim(new RunId(self::OTHER_RUN), self::OTHER_STATE_DIRECTORY);
            self::fail('A second run claimed the store.');
        } catch (RunClaimedElsewhere $refused) {
            self::assertSame(self::RUN, $refused->runId());
            self::assertSame(self::STATE_DIRECTORY, $refused->stateDirectory());
            self::assertStringContainsString(self::RUN, $refused->getMessage());
            self::assertStringContainsString(self::STATE_DIRECTORY, $refused->getMessage());
        }

        self::assertSame(['run_id' => self::RUN, 'state_directory' => self::STATE_DIRECTORY], $this->registry()->claimed());
    }

    public function testAReleasedClaimLetsTheNextRunClaim(): void
    {
        $this->registry()->claim(new RunId(self::RUN), self::STATE_DIRECTORY);

        $this->registry()->release(new RunId(self::RUN));

        self::assertNull($this->otherProcess()->claimed());
        $this->otherProcess()->claim(new RunId(self::OTHER_RUN), self::OTHER_STATE_DIRECTORY);
        self::assertSame(['run_id' => self::OTHER_RUN, 'state_directory' => self::OTHER_STATE_DIRECTORY], $this->registry()->claimed());
    }

    public function testAReleaseByAnotherRunLeavesTheClaim(): void
    {
        $this->registry()->claim(new RunId(self::RUN), self::STATE_DIRECTORY);

        $this->otherProcess()->release(new RunId(self::OTHER_RUN));

        self::assertSame(['run_id' => self::RUN, 'state_directory' => self::STATE_DIRECTORY], $this->registry()->claimed());
    }

    public function testReleasingWithoutAClaimDoesNothing(): void
    {
        $this->registry()->release(new RunId(self::RUN));

        self::assertNull($this->registry()->claimed());
    }
}
