<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Fixtures\Factory\UnwirableService;

final class Mailer
{
    public function __construct(
        public readonly string $from,
        public readonly ?Transport $transport,
    ) {}
}
