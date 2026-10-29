<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web;

/**
 * The web tier could not be asked: the probe file could not be put in place, the transport could not
 * reach the web tier, or the answer was not the probe's. The message is the reason for the operator:
 * it may carry an address, a path or a status line, never the probe's token or a response body.
 */
final class ProbeUnreachable extends \RuntimeException {}
