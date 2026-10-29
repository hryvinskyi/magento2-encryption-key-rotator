<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Infrastructure\Database;

use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\JitteredRetryPause;
use PHPUnit\Framework\TestCase;

/**
 * The pause after the first failed attempt is a random wait of at most a tenth of a second.
 */
final class JitteredRetryPauseTest extends TestCase
{
    public function testTheFirstPauseIsShort(): void
    {
        $started = hrtime(true);

        (new JitteredRetryPause())->after(1);

        self::assertLessThan(0.25, (hrtime(true) - $started) / 1e9);
    }
}
