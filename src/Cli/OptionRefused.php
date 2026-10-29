<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Cli;

/**
 * A command's options cannot be acted on: a path that is no Magento root, a malformed probe setting, a
 * key file others can read, no way chosen to confirm the web tier, a confirmation not given. Raised
 * before the command writes anything; the console application reports it as a refusal.
 */
final class OptionRefused extends \InvalidArgumentException {}
