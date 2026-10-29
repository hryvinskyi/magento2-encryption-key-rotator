<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeStatus;
use Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase\Support\RotationWorld;
use PHPUnit\Framework\TestCase;

/**
 * Waiting for the web tier asks every five seconds until it holds the ring or the wait is spent.
 */
final class WebTierConfirmationTest extends TestCase
{
    private RotationWorld $world;

    protected function setUp(): void
    {
        $this->world = new RotationWorld();
    }

    protected function tearDown(): void
    {
        $this->world->cleanUp();
    }

    public function testItAsksEveryFiveSecondsUntilTheBudgetIsSpentAndReturnsTheLastAnswer(): void
    {
        $world = $this->world;
        $world->probe->answerFromNowOn(new ProbeOutcome(ProbeStatus::Unreachable, 'The socket refused the connection.'));
        $started = $world->clock->now();

        $outcome = $world->webTier->await($world->ringBefore, $world->probeSettings(waitSeconds: 12));

        self::assertSame(ProbeStatus::Unreachable, $outcome->status());
        self::assertCount(4, $world->probe->observed(), 'Asked at 0, 5, 10 and 12 seconds.');
        self::assertSame([5, 5, 2], $world->pause->pauses(), 'The waits between the questions go through the pause.');
        self::assertSame(12, $world->clock->now()->getTimestamp() - $started->getTimestamp());
    }

    public function testItStopsAsSoonAsTheWebTierHoldsTheRing(): void
    {
        $world = $this->world;
        $world->probe->enqueue($world->differs(), $world->differs(), $world->matches());
        $started = $world->clock->now();

        $outcome = $world->webTier->await($world->ringBefore, $world->probeSettings(waitSeconds: 120));

        self::assertTrue($outcome->matches());
        self::assertCount(3, $world->probe->observed());
        self::assertSame(10, $world->clock->now()->getTimestamp() - $started->getTimestamp());
    }

    public function testWithoutAWaitItAsksOnce(): void
    {
        $world = $this->world;
        $world->probe->answerFromNowOn($world->differs());

        $outcome = $world->webTier->await($world->ringBefore, $world->probeSettings(waitSeconds: 0));

        self::assertFalse($outcome->matches());
        self::assertSame([$world->ringBefore->fingerprint()], $world->probe->observed());
    }

    public function testOnceAsksASingleTime(): void
    {
        $world = $this->world;
        $world->probe->answerFromNowOn($world->differs());

        $world->webTier->once($world->ringBefore);

        self::assertCount(1, $world->probe->observed());
    }
}
