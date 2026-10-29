<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Fixtures\Factory\UnwirableService;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

#[CreatesInstancesOf(Mailer::class)]
interface MailerFactory
{
    public function create(string $from): Mailer;
}
