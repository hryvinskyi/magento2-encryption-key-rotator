<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Cli\Context;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\MagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\MagentoRootProvider;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ProbeSettingsProvider;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\StateDirectoryProvider;

/**
 * What the running command was told about the store: its Magento root, its state directory and how the
 * web tier is probed. The services are built before any command runs, so the context starts empty and
 * is filled from the command's options once the command starts ({@see CommandContextListener}); asking
 * before then is a programming error and fails loudly instead of guessing a root.
 */
final class CommandContext implements MagentoRootProvider, StateDirectoryProvider, ProbeSettingsProvider
{
    private ?MagentoRoot $root = null;

    private ?string $stateDirectory = null;

    private ?ProbeSettings $probeSettings = null;

    /**
     * @param MagentoRoot $root           the root the command works on
     * @param string      $stateDirectory the absolute path of the state directory
     */
    public function useStore(MagentoRoot $root, string $stateDirectory): void
    {
        $this->root = $root;
        $this->stateDirectory = $stateDirectory;
    }

    public function useProbeSettings(ProbeSettings $settings): void
    {
        $this->probeSettings = $settings;
    }

    /**
     * @throws \LogicException when no command has set the root yet
     */
    public function root(): MagentoRoot
    {
        return $this->root ?? throw new \LogicException(
            'The Magento root is not known yet: it is set from --magento-root when a command starts, and no command has started.',
        );
    }

    /**
     * @throws \LogicException when no command has set the state directory yet
     */
    public function directory(): string
    {
        return $this->stateDirectory ?? throw new \LogicException(
            'The state directory is not known yet: it is set from --state-dir when a command starts, and no command has started.',
        );
    }

    /**
     * @throws \LogicException when the running command took no probe options
     */
    public function settings(): ProbeSettings
    {
        return $this->probeSettings ?? throw new \LogicException(
            'The probe settings are not known: only rotate, retire and rollback take them, from their probe options.',
        );
    }
}
