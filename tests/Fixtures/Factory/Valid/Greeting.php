<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Fixtures\Factory\Valid;

use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Created with two runtime arguments, one autowired service and one container parameter.
 */
final class Greeting
{
    public function __construct(
        public readonly string $name,
        public readonly int $times,
        public readonly Punctuation $punctuation,
        #[Autowire('%fixture.separator%')]
        public readonly string $separator,
    ) {}

    public function text(): string
    {
        return implode($this->separator, array_fill(0, $this->times, 'Hello ' . $this->name . $this->punctuation->mark()));
    }
}
