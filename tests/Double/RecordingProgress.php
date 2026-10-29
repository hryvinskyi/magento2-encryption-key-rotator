<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\Progress;

/**
 * Progress output kept in memory, so a test can read what a use case told the operator, and check it
 * told no secret.
 */
final class RecordingProgress implements Progress
{
    /**
     * @var list<string>
     */
    private array $steps = [];

    /**
     * @var array<string, int> `table.column` => values advanced
     */
    private array $advanced = [];

    /**
     * @var list<string>
     */
    private array $warnings = [];

    public function step(string $message): void
    {
        $this->steps[] = $message;
    }

    public function advance(ColumnRef $column, int $count): void
    {
        $this->advanced[$column->toString()] = ($this->advanced[$column->toString()] ?? 0) + $count;
    }

    public function warn(string $message): void
    {
        $this->warnings[] = $message;
    }

    /**
     * @return list<string>
     */
    public function steps(): array
    {
        return $this->steps;
    }

    /**
     * @return array<string, int> `table.column` => values advanced
     */
    public function advanced(): array
    {
        return $this->advanced;
    }

    /**
     * @return list<string>
     */
    public function warnings(): array
    {
        return $this->warnings;
    }

    /**
     * Everything told, in one text, for asserting that a secret never appears in it.
     */
    public function transcript(): string
    {
        return implode("\n", [...$this->steps, ...$this->warnings, ...array_keys($this->advanced)]);
    }
}
