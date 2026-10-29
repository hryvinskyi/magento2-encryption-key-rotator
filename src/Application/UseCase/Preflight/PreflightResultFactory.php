<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Preflight;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\RunningProcess;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\Refusal;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunOverride;
use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see PreflightResult} values; implemented by the container build.
 */
#[CreatesInstancesOf(PreflightResult::class)]
interface PreflightResultFactory
{
    /**
     * @param list<Refusal>        $refusals
     * @param list<RunningProcess> $workers
     * @param list<RunOverride>    $waived
     */
    public function create(array $refusals, array $workers, array $waived): PreflightResult;
}
