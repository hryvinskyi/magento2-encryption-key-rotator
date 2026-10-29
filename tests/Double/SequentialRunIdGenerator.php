<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double;

use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunIdGenerator;

/**
 * Draws predictable run ids, `000…001`, `000…002`, …, so a test can name the run a use case starts.
 */
final class SequentialRunIdGenerator implements RunIdGenerator
{
    private int $issued = 0;

    public function next(): RunId
    {
        return self::id(++$this->issued);
    }

    /**
     * The id the generator issues as its n-th.
     */
    public static function id(int $n): RunId
    {
        return new RunId(str_pad(dechex($n), 32, '0', STR_PAD_LEFT));
    }
}
