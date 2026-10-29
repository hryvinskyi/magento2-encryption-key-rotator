<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;

/**
 * Tells the operator what a use case is doing while it runs. Messages never carry a key, a plaintext
 * or a password.
 */
interface Progress
{
    /**
     * A step starts.
     */
    public function step(string $message): void;

    /**
     * That many more values of a column were handled.
     */
    public function advance(ColumnRef $column, int $count): void;

    /**
     * Something went wrong that does not stop the step.
     */
    public function warn(string $message): void;
}
