<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunClaimedElsewhere;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunRegistry;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;

/**
 * The store's claim in memory, with the semantics of the table: one claim at most, kept until the run
 * that holds it releases it. A test plays a run of another state directory by claiming for it directly.
 */
final class InMemoryRunRegistry implements RunRegistry
{
    /**
     * @var array{run_id: string, state_directory: string}|null
     */
    private ?array $claim = null;

    public function __construct(
        private readonly ?CallLog $log = null,
    ) {}

    public function claim(RunId $id, string $stateDirectory): void
    {
        if ($this->claim !== null && $this->claim['run_id'] !== $id->toString()) {
            throw new RunClaimedElsewhere($this->claim['run_id'], $this->claim['state_directory']);
        }
        if ($this->claim === null) {
            $this->claim = ['run_id' => $id->toString(), 'state_directory' => $stateDirectory];
            $this->log?->record('registry.claim ' . $id->toString());
        }
    }

    public function claimed(): ?array
    {
        return $this->claim;
    }

    public function release(RunId $id): void
    {
        if ($this->claim !== null && $this->claim['run_id'] === $id->toString()) {
            $this->claim = null;
            $this->log?->record('registry.release ' . $id->toString());
        }
    }
}
