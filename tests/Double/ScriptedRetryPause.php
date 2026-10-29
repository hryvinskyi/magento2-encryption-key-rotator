<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double;

use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\RetryPause;

/**
 * Records every pause before a retry instead of waiting, and runs an optional action at each one: the
 * place for a test to release a lock between two attempts.
 */
final class ScriptedRetryPause implements RetryPause
{
    /**
     * @var list<int>
     */
    private array $attempts = [];

    /**
     * @param (\Closure(int): void)|null $onPause
     */
    public function __construct(
        private readonly ?\Closure $onPause = null,
    ) {}

    public function after(int $attempt): void
    {
        $this->attempts[] = $attempt;
        if ($this->onPause !== null) {
            ($this->onPause)($attempt);
        }
    }

    /**
     * @return list<int> the failed attempts each pause followed, in order
     */
    public function attempts(): array
    {
        return $this->attempts;
    }
}
