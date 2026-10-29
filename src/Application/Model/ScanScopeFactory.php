<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see ScanScope} values; implemented by the container build.
 */
#[CreatesInstancesOf(ScanScope::class)]
interface ScanScopeFactory
{
    /**
     * @param list<string> $exclusions `table` or `table.column` patterns, `*` as the wildcard
     *
     * @throws InvalidValue when a pattern is malformed
     */
    public function create(array $exclusions): ScanScope;
}
