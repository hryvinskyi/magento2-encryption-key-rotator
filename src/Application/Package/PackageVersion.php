<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Package;

/**
 * The version of the tool that is running.
 */
interface PackageVersion
{
    /**
     * @return string a version such as `1.2.0`, a development version with its commit, or `unknown`
     */
    public function version(): string;
}
