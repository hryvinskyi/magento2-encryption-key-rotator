<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Preflight;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\RunningProcess;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\Refusal;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunOverride;

/**
 * What the checks before a write found: every refusal, the processes that may still hold an earlier key
 * ring, and the checks the operator waived and that did waive something (the caller records them on the
 * run).
 *
 * Created through {@see PreflightResultFactory}.
 */
final class PreflightResult
{
    /**
     * @param list<Refusal>        $refusals every check that refused
     * @param list<RunningProcess> $workers  the processes that started before the key ring write checked against
     * @param list<RunOverride>    $waived   the overrides that let a failing check pass
     */
    public function __construct(
        private readonly array $refusals,
        private readonly array $workers,
        private readonly array $waived,
    ) {}

    /**
     * Whether nothing refused.
     */
    public function passed(): bool
    {
        return $this->refusals === [];
    }

    /**
     * @return list<Refusal>
     */
    public function refusals(): array
    {
        return $this->refusals;
    }

    /**
     * @return list<RunningProcess>
     */
    public function workers(): array
    {
        return $this->workers;
    }

    /**
     * @return list<RunOverride>
     */
    public function waived(): array
    {
        return $this->waived;
    }
}
