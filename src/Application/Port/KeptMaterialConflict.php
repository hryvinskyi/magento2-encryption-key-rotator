<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

/**
 * A run already keeps different material under the same name: another key for the same role and
 * index, or another set of placeholders. What was kept first stays; the message names no key.
 */
final class KeptMaterialConflict extends \RuntimeException {}
