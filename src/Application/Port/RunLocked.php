<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

/**
 * Another process holds the lock of the state directory: one run at a time per Magento root.
 */
final class RunLocked extends \RuntimeException {}
