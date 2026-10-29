<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

/**
 * A process of the store that holds the key ring it read when it started: a cron run, a queue consumer,
 * a long command. Its start time may be unknown, and an unknown start counts as earlier than any key
 * ring write: such a process may hold any earlier ring.
 *
 * Created through {@see RunningProcessFactory}.
 */
final class RunningProcess
{
    /**
     * @param string                  $description what runs, for the operator (a command line, a job code)
     * @param \DateTimeImmutable|null $startedAt   when it started, or null when that is unknown
     */
    public function __construct(
        private readonly string $description,
        private readonly ?\DateTimeImmutable $startedAt,
    ) {}

    public function description(): string
    {
        return $this->description;
    }

    public function startedAt(): ?\DateTimeImmutable
    {
        return $this->startedAt;
    }

    /**
     * Whether the process may still hold the key ring from before that moment: it started before it, or
     * its start is unknown.
     */
    public function startedBefore(\DateTimeImmutable $moment): bool
    {
        return $this->startedAt === null || $this->startedAt < $moment;
    }
}
