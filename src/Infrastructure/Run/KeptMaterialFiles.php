<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\KeptKeyRole;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\KeptMaterialConflict;
use Hryvinskyi\EncryptionKeyRotator\Application\Run\CorruptRunFile;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeySlot;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeySlotFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;

/**
 * The ring entries a run keeps in its directory to undo itself, in two files readable by their owner
 * only:
 *
 * - `keys.json`, the keys by role and index: `{"added": [{"index": 3, "entry": "…"}], "retired": […]}`;
 * - `placeholders.json`, the placeholders a pending retirement writes: `{"placeholders": [{"index": 0, "entry": "…"}]}`.
 *
 * What is kept is never replaced: keeping the same entry or set again changes nothing, keeping another
 * one under the same name fails and leaves the first. Every change rewrites its file atomically, so a
 * crash keeps either the old file or the new one. A message names the run, the role and the index,
 * never an entry.
 */
final class KeptMaterialFiles
{
    private const PLACEHOLDERS = 'placeholders';

    public function __construct(
        private readonly RunDirectoryLayout $layout,
        private readonly PrivateJsonFile $json,
        private readonly KeySlotFactory $slots,
    ) {}

    /**
     * @throws KeptMaterialConflict when the run keeps another entry for that role and index
     */
    public function keepKey(RunId $id, KeptKeyRole $role, KeySlot $slot): void
    {
        $file = $this->layout->runFile($id, RunDirectoryLayout::KEYS_FILE);
        $kept = $this->readKeys($id, $file);
        $existing = $kept[$role->value][$slot->index()] ?? null;
        if ($existing !== null) {
            if (!hash_equals($existing, $slot->raw())) {
                throw new KeptMaterialConflict(sprintf(
                    'Run %s already keeps another %s key for slot %d; the kept key stays.',
                    $id->toString(),
                    $role->value,
                    $slot->index(),
                ));
            }

            return;
        }

        $kept[$role->value][$slot->index()] = $slot->raw();
        $data = [];
        foreach (KeptKeyRole::cases() as $case) {
            $data[$case->value] = $this->entries($kept[$case->value] ?? []);
        }
        $this->layout->ensureRunDirectory($id);
        $this->json->write($file, $data);
    }

    /**
     * @return list<KeySlot> the entries kept for the role, in index order
     */
    public function keptKeys(RunId $id, KeptKeyRole $role): array
    {
        $kept = $this->readKeys($id, $this->layout->runFile($id, RunDirectoryLayout::KEYS_FILE));

        return $this->toSlots($kept[$role->value] ?? []);
    }

    /**
     * @param list<KeySlot> $placeholders
     *
     * @throws KeptMaterialConflict when the run keeps another set
     */
    public function keepPlaceholders(RunId $id, array $placeholders): void
    {
        $given = [];
        foreach ($placeholders as $slot) {
            $given[$slot->index()] = $slot->raw();
        }
        ksort($given);

        $file = $this->layout->runFile($id, RunDirectoryLayout::PLACEHOLDERS_FILE);
        if ($this->json->exists($file)) {
            if ($this->readPlaceholders($id, $file) !== $given) {
                throw new KeptMaterialConflict(sprintf(
                    'Run %s already keeps another set of placeholders; the kept set stays.',
                    $id->toString(),
                ));
            }

            return;
        }

        $this->layout->ensureRunDirectory($id);
        $this->json->write($file, [self::PLACEHOLDERS => $this->entries($given)]);
    }

    /**
     * @return list<KeySlot> the kept placeholders, in index order
     */
    public function keptPlaceholders(RunId $id): array
    {
        $file = $this->layout->runFile($id, RunDirectoryLayout::PLACEHOLDERS_FILE);
        if (!$this->json->exists($file)) {
            return [];
        }

        return $this->toSlots($this->readPlaceholders($id, $file));
    }

    /**
     * @return array<string, array<int, string>> role => index => entry
     */
    private function readKeys(RunId $id, string $file): array
    {
        if (!$this->json->exists($file)) {
            return [];
        }
        $what = sprintf('the kept keys of run %s', $id->toString());
        $data = $this->json->read($file, $what);
        if (!is_array($data)) {
            $this->corrupt($what, 'it is not an object');
        }

        $kept = [];
        foreach (KeptKeyRole::cases() as $role) {
            $kept[$role->value] = $this->indexed($data[$role->value] ?? [], $what, $role->value);
        }

        return $kept;
    }

    /**
     * @return array<int, string> index => entry, in index order
     */
    private function readPlaceholders(RunId $id, string $file): array
    {
        $what = sprintf('the kept placeholders of run %s', $id->toString());
        $data = $this->json->read($file, $what);
        if (!is_array($data) || !array_key_exists(self::PLACEHOLDERS, $data)) {
            $this->corrupt($what, sprintf('it holds no "%s"', self::PLACEHOLDERS));
        }

        return $this->indexed($data[self::PLACEHOLDERS], $what, self::PLACEHOLDERS);
    }

    /**
     * @return array<int, string> index => entry, in index order
     */
    private function indexed(mixed $entries, string $what, string $field): array
    {
        if (!is_array($entries) || !array_is_list($entries)) {
            $this->corrupt($what, sprintf('"%s" is not a list', $field));
        }
        $indexed = [];
        foreach ($entries as $entry) {
            $index = is_array($entry) ? ($entry['index'] ?? null) : null;
            $raw = is_array($entry) ? ($entry['entry'] ?? null) : null;
            if (!is_int($index) || !is_string($raw) || array_key_exists($index, $indexed)) {
                $this->corrupt($what, sprintf('an entry of "%s" is not one index with one entry', $field));
            }
            $indexed[$index] = $raw;
        }
        ksort($indexed);

        return $indexed;
    }

    /**
     * @param array<int, string> $entries
     *
     * @return list<array{index: int, entry: string}>
     */
    private function entries(array $entries): array
    {
        ksort($entries);
        $list = [];
        foreach ($entries as $index => $raw) {
            $list[] = ['index' => $index, 'entry' => $raw];
        }

        return $list;
    }

    /**
     * @param array<int, string> $entries
     *
     * @return list<KeySlot>
     */
    private function toSlots(array $entries): array
    {
        $slots = [];
        foreach ($entries as $index => $raw) {
            $slots[] = $this->slots->create($index, $raw);
        }

        return $slots;
    }

    /**
     * @throws CorruptRunFile always, naming what is corrupt and why
     */
    private function corrupt(string $what, string $reason): never
    {
        throw new CorruptRunFile(sprintf('%s are corrupt: %s.', ucfirst($what), $reason));
    }
}
