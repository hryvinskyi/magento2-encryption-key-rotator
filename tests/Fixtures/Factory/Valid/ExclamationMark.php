<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Fixtures\Factory\Valid;

final class ExclamationMark implements Punctuation
{
    public function mark(): string
    {
        return '!';
    }
}
