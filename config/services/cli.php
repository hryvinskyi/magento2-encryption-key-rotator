<?php

declare(strict_types=1);

use Hryvinskyi\EncryptionKeyRotator\Application\Port\MagentoRootProvider;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ProbeSettingsProvider;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\Progress;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\StateDirectoryProvider;
use Hryvinskyi\EncryptionKeyRotator\Cli\Context\CommandContext;
use Hryvinskyi\EncryptionKeyRotator\Cli\Context\CommandContextListener;
use Hryvinskyi\EncryptionKeyRotator\Cli\ExitCode;
use Hryvinskyi\EncryptionKeyRotator\Cli\Output\ConsoleProgress;
use Symfony\Component\Console\Helper\QuestionHelper;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\EventDispatcher\EventDispatcher;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/*
 * The console side: what a command learns from its options reaches the adapters through the command
 * context, which implements the Magento root, state directory and probe settings ports; the use cases'
 * progress goes to the running command's output. Both are filled by the context listener, subscribed to
 * the dispatcher the console application announces every command on.
 */
return static function (ContainerConfigurator $container): void {
    $services = $container->services()
        ->defaults()
        ->autowire()
        ->autoconfigure()
        ->private();

    $services->alias(MagentoRootProvider::class, CommandContext::class);
    $services->alias(StateDirectoryProvider::class, CommandContext::class);
    $services->alias(ProbeSettingsProvider::class, CommandContext::class);
    $services->alias(Progress::class, ConsoleProgress::class);

    $services->get(EventDispatcher::class)
        ->call('addSubscriber', [service(CommandContextListener::class)]);

    $services->set(QuestionHelper::class);

    $services->remove(ExitCode::class);
};
