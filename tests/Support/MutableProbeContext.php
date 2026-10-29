<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Support;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\MagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\MagentoRootProvider;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ProbeSettingsProvider;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\StateDirectoryProvider;

/**
 * The command context a compiled container's adapters ask for, set by the test the way a command sets
 * it once it has read its options.
 */
final class MutableProbeContext implements MagentoRootProvider, ProbeSettingsProvider, StateDirectoryProvider
{
    private ?MagentoRoot $root = null;

    private ?ProbeSettings $settings = null;

    private ?string $stateDirectory = null;

    public function use(MagentoRoot $root, ProbeSettings $settings, string $stateDirectory): void
    {
        $this->root = $root;
        $this->settings = $settings;
        $this->stateDirectory = $stateDirectory;
    }

    public function useSettings(ProbeSettings $settings): void
    {
        $this->settings = $settings;
    }

    public function root(): MagentoRoot
    {
        return $this->root ?? throw new \LogicException('The test set no Magento root.');
    }

    public function settings(): ProbeSettings
    {
        return $this->settings ?? throw new \LogicException('The test set no probe settings.');
    }

    public function directory(): string
    {
        return $this->stateDirectory ?? throw new \LogicException('The test set no state directory.');
    }
}
