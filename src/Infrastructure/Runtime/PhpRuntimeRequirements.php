<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Runtime;

use Hryvinskyi\EncryptionKeyRotator\Application\Requirements\RequirementsReport;
use Hryvinskyi\EncryptionKeyRotator\Application\Requirements\RequirementsReportFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Requirements\RuntimeRequirements;

/**
 * Reads the requirements from the PHP process itself.
 */
final class PhpRuntimeRequirements implements RuntimeRequirements
{
    private const REQUIRED_EXTENSIONS = ['sodium', 'pdo_mysql', 'json'];

    public function __construct(
        private readonly RequirementsReportFactory $reports,
    ) {}

    public function check(): RequirementsReport
    {
        $extensions = [];
        foreach (self::REQUIRED_EXTENSIONS as $extension) {
            $extensions[$extension] = extension_loaded($extension);
        }

        return $this->reports->create(PHP_VERSION, $extensions);
    }
}
