<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Run;

/**
 * A state change the run's current state does not allow. The message names the run, the state it is
 * in and the state that was asked for.
 */
final class IllegalRunTransition extends \DomainException {}
