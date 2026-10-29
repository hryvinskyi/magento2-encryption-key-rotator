<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double;

/**
 * The order in which doubles were called, shared by every double a test hands it to, so a test can
 * assert that one step happened before another (the probe matched before any value moved).
 *
 * Events are short strings such as `config.write <fingerprint>`, `probe.observe <fingerprint>`,
 * `db.apply forward 3`, `db.revert 2`, `db.supersede`, `cache.clean`, `store.save <state>`.
 */
final class CallLog
{
    /**
     * @var list<string>
     */
    private array $events = [];

    public function record(string $event): void
    {
        $this->events[] = $event;
    }

    /**
     * @return list<string> every event, oldest first
     */
    public function events(): array
    {
        return $this->events;
    }

    /**
     * @return list<string> the events that start with the prefix, oldest first
     */
    public function eventsStartingWith(string $prefix): array
    {
        return array_values(array_filter($this->events, static fn(string $event): bool => str_starts_with($event, $prefix)));
    }

    /**
     * The position of the first event that starts with the prefix, or null when none does.
     */
    public function firstPosition(string $prefix): ?int
    {
        foreach ($this->events as $position => $event) {
            if (str_starts_with($event, $prefix)) {
                return $position;
            }
        }

        return null;
    }
}
