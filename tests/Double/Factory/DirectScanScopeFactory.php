<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanScope;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanScopeFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectScanScopeFactory implements ScanScopeFactory
{
    public function create(array $exclusions): ScanScope
    {
        return new ScanScope($exclusions);
    }
}
