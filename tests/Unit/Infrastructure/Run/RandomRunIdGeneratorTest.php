<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Infrastructure\Run;

use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run\RandomRunIdGenerator;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectRunIdFactory;
use PHPUnit\Framework\TestCase;

final class RandomRunIdGeneratorTest extends TestCase
{
    public function testEveryIdIsAValidRunIdAndNoneRepeats(): void
    {
        $generator = new RandomRunIdGenerator(new DirectRunIdFactory());

        $ids = [];
        for ($i = 0; $i < 200; $i++) {
            $ids[] = $generator->next()->toString();
        }

        self::assertCount(200, array_unique($ids));
        foreach ($ids as $id) {
            self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/D', $id);
        }
    }
}
