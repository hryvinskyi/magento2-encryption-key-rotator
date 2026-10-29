<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

/**
 * What a scan found for one encrypted `system` value of a configuration file: the value, with the file
 * that holds it, and its {@see ValueVerdict}.
 *
 * Created through {@see SystemValueFindingFactory}.
 */
final class SystemValueFinding
{
    public function __construct(
        private readonly SystemValue $value,
        private readonly ValueVerdict $verdict,
    ) {}

    public function value(): SystemValue
    {
        return $this->value;
    }

    public function verdict(): ValueVerdict
    {
        return $this->verdict;
    }

    public function source(): SystemValueSource
    {
        return $this->value->source();
    }

    public function keyIndex(): int
    {
        return $this->value->ciphertext()->keyIndex();
    }
}
