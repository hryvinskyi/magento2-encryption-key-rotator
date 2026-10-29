<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Cli\Confirmation\QuestionFactory;
use Symfony\Component\Console\Question\Question;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectQuestionFactory implements QuestionFactory
{
    public function create(string $question): Question
    {
        return new Question($question);
    }
}
