<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Runtime;

use Composer\InstalledVersions;
use Hryvinskyi\EncryptionKeyRotator\Application\Package\PackageVersion;

/**
 * Reads the version Composer recorded for this package when its dependencies were installed (the
 * `version` of composer.json, the tag, or the branch and commit of the checkout).
 */
final class ComposerPackageVersion implements PackageVersion
{
    private const PACKAGE = 'hryvinskyi/magento2-encryption-key-rotator';
    private const UNKNOWN = 'unknown';

    public function version(): string
    {
        if (!class_exists(InstalledVersions::class) || !InstalledVersions::isInstalled(self::PACKAGE)) {
            return self::UNKNOWN;
        }
        $version = InstalledVersions::getPrettyVersion(self::PACKAGE);
        if ($version === null) {
            return self::UNKNOWN;
        }
        $reference = InstalledVersions::getReference(self::PACKAGE);
        if (str_starts_with($version, 'dev-') && $reference !== null && $reference !== '') {
            return $version . '@' . substr($reference, 0, 7);
        }

        return $version;
    }
}
