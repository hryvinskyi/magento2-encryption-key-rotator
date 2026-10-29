<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Cli\Confirmation;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;
use Symfony\Component\Console\Question\Question;

/**
 * Creates the questions a command asks the operator; implemented by the container build.
 */
#[CreatesInstancesOf(Question::class)]
interface QuestionFactory
{
    public function create(string $question): Question;
}
