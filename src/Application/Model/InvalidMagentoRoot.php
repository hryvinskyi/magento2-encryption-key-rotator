<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

/**
 * A path that is not the root of a Magento installation: not absolute, or without `app/etc/env.php`.
 */
final class InvalidMagentoRoot extends \InvalidArgumentException {}
