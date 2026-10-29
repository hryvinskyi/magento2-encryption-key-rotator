<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Cli\Context;

use Hryvinskyi\EncryptionKeyRotator\Cli\Option\CommandOptions;
use Hryvinskyi\EncryptionKeyRotator\Cli\OptionRefused;
use Hryvinskyi\EncryptionKeyRotator\Cli\Output\ConsoleProgress;
use Symfony\Component\Console\ConsoleEvents;
use Symfony\Component\Console\Event\ConsoleCommandEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Fills the command context when a command starts, after the console has bound its options and before
 * the command runs: the progress output, then the Magento root and the state directory of a command
 * that takes the store options, then the probe settings of a command that takes the probe options. The
 * services were built before this, which is why none of them may read the root in its constructor.
 */
final class CommandContextListener implements EventSubscriberInterface
{
    public function __construct(
        private readonly CommandContext $context,
        private readonly ConsoleProgress $progress,
        private readonly CommandOptions $options,
    ) {}

    /**
     * @return array<string, string>
     */
    public static function getSubscribedEvents(): array
    {
        return [ConsoleEvents::COMMAND => 'onCommand'];
    }

    /**
     * @throws OptionRefused when an option names no Magento root or a malformed probe setting
     */
    public function onCommand(ConsoleCommandEvent $event): void
    {
        $this->progress->useOutput($event->getOutput());

        $command = $event->getCommand();
        if ($command === null || !$this->options->definesStoreOptions($command)) {
            return;
        }
        $input = $event->getInput();
        $root = $this->options->magentoRoot($input);
        $this->context->useStore($root, $this->options->stateDirectory($input, $root));

        if ($this->options->definesProbeOptions($command)) {
            $this->context->useProbeSettings($this->options->probeSettings($input));
        }
    }
}
