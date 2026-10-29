<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnCandidate;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanScope;

/**
 * Discovers the columns of the store's database that hold encrypted values, by the shape of their
 * values: a ciphertext `<key index>:<cipher version>:<base64>` as the whole value, or embedded inside a
 * larger one. The tool's own journal is never a candidate.
 */
interface EncryptedColumnFinder
{
    /**
     * @return list<ColumnCandidate> every column the scope does not exclude that holds a ciphertext-shaped
     *                               or embedded value, or whose scan the database cut short
     */
    public function candidates(ScanScope $scope): array;
}
