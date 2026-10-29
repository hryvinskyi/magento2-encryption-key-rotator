<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Reencryption;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnCandidate;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Direction;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\InvalidValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Reencryption;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ReencryptionFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanScope;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\StoredValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ValueVerdict;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\CiphertextRows;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\EncryptedColumnFinder;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalSchema;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\Progress;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ReencryptionWriter;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Cipher;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\CiphertextParser;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\RoundTripFailed;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\Key;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;

/**
 * Moves the database's values from source keys onto a target key, for a run, in either direction.
 *
 * For every column with a row key that holds values under a source index, it reads the values batch by
 * batch, decrypts each under its source key, encrypts the plaintext under the target key (the cipher
 * decrypts the new value and compares it before handing it back) and writes the batch by
 * compare-and-swap on the exact old bytes, journaled in the same transaction. Plaintexts live only for
 * the moment between the two cipher calls.
 *
 * - A value that does not decrypt under its source key is never written; it is counted as left alone.
 * - A row whose value changed between the read and the write is a conflict: its newer value is kept. The
 *   column is read again in the next pass, so a newer value still under a source index moves too; after
 *   three passes whatever is still missed is reported.
 * - Only values under a source index are read, so running the service again touches nothing it already
 *   moved.
 */
final class ReencryptColumnValues
{
    public const MAX_PASSES = 3;

    public function __construct(
        private readonly EncryptedColumnFinder $finder,
        private readonly CiphertextRows $rows,
        private readonly ReencryptionWriter $writer,
        private readonly JournalSchema $journal,
        private readonly CiphertextParser $parser,
        private readonly Cipher $cipher,
        private readonly ReencryptionFactory $reencryptions,
        private readonly ReencryptionOutcomeFactory $outcomes,
        private readonly Progress $progress,
    ) {}

    /**
     * @param RunId           $runId       the run the journal entries belong to
     * @param Direction       $direction   forward onto the appended key, or back onto the key active before the run
     * @param array<int, Key> $sources     key index => key, the values to move
     * @param int             $targetIndex the index the values move to
     * @param Key             $targetKey   the key of that index
     * @param ScanScope       $scope       the columns left out
     * @param int             $batchSize   the most values read and written at once, at least 1
     *
     * @throws InvalidValue    when no source is given, the target is one of them, or the batch size is below 1
     * @throws RoundTripFailed when a new value does not decrypt back to its plaintext; nothing of its batch is written
     */
    public function reencrypt(
        RunId $runId,
        Direction $direction,
        array $sources,
        int $targetIndex,
        Key $targetKey,
        ScanScope $scope,
        int $batchSize,
    ): ReencryptionOutcome {
        if ($sources === []) {
            throw new InvalidValue('A re-encryption moves values from at least one key.');
        }
        if (array_key_exists($targetIndex, $sources)) {
            throw new InvalidValue(sprintf('The key index %d cannot be a source and the target of the same re-encryption.', $targetIndex));
        }
        if ($batchSize < 1) {
            throw new InvalidValue('A re-encryption reads at least one value at a time.');
        }
        $this->journal->ensure();

        /** @var array<string, array{candidate: ColumnCandidate, indices: list<int>}> $pending */
        $pending = [];
        foreach ($this->finder->candidates($scope) as $candidate) {
            $indices = array_values(array_filter(
                array_keys($sources),
                static fn(int $index): bool => $candidate->shapeCountOn($index) > 0,
            ));
            if ($candidate->hasRowKey() && $indices !== []) {
                $pending[$candidate->column()->toString()] = ['candidate' => $candidate, 'indices' => $indices];
            }
        }

        $applied = [];
        $skipped = [];
        $conflicts = [];
        $passes = 0;
        while ($pending !== [] && $passes < self::MAX_PASSES) {
            $passes++;
            $conflicts = [];
            $retry = [];
            foreach ($pending as $name => $work) {
                $column = $work['candidate']->column();
                $skipped[$name] = [];
                $columnConflicts = [];
                foreach ($work['indices'] as $index) {
                    foreach ($this->rows->batches($column, $index, $batchSize) as $batch) {
                        $writes = [];
                        foreach ($batch as $stored) {
                            $write = $this->reencryption($stored, $work['candidate'], $index, $sources[$index], $targetIndex, $targetKey);
                            if ($write instanceof Reencryption) {
                                $writes[] = $write;
                            } else {
                                $skipped[$name][$write->value] = ($skipped[$name][$write->value] ?? 0) + 1;
                            }
                        }
                        if ($writes === []) {
                            continue;
                        }
                        $result = $this->writer->apply($runId, $direction, $writes);
                        $applied[$name] = ($applied[$name] ?? 0) + $result->applied();
                        $columnConflicts = [...$columnConflicts, ...$result->conflicts()];
                        $this->progress->advance($column, $result->applied());
                    }
                }
                if ($skipped[$name] === []) {
                    unset($skipped[$name]);
                }
                if ($columnConflicts !== []) {
                    $conflicts = [...$conflicts, ...$columnConflicts];
                    $retry[$name] = ['candidate' => $work['candidate'], 'indices' => array_keys($sources)];
                }
            }
            $pending = $retry;
        }

        return $this->outcomes->create($applied, $conflicts, $skipped, $passes);
    }

    /**
     * The write that moves the value, or why it stays where it is.
     */
    private function reencryption(
        StoredValue $stored,
        ColumnCandidate $candidate,
        int $sourceIndex,
        Key $sourceKey,
        int $targetIndex,
        Key $targetKey,
    ): Reencryption|ValueVerdict {
        $ciphertext = $this->parser->parse($stored->raw());
        if ($ciphertext === null || $ciphertext->keyIndex() !== $sourceIndex) {
            return ValueVerdict::Unparsable;
        }
        if (!$this->cipher->supports($ciphertext->cipherVersion())) {
            return ValueVerdict::UnsupportedCipher;
        }
        $plaintext = $this->cipher->decrypt($ciphertext, $sourceKey);
        if ($plaintext === null) {
            return ValueVerdict::AuthenticationFailed;
        }

        return $this->reencryptions->create(
            $candidate->column(),
            $stored->rowKey(),
            $stored->raw(),
            $this->cipher->encrypt($plaintext, $targetIndex, $targetKey),
        );
    }
}
