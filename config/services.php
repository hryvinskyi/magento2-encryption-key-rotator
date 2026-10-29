<?php

declare(strict_types=1);

use Hryvinskyi\EncryptionKeyRotator\Application\Package\PackageVersion;
use Hryvinskyi\EncryptionKeyRotator\Application\Requirements\RuntimeRequirements;
use Hryvinskyi\EncryptionKeyRotator\Cli\ConsoleApplication;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Cipher;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyGenerator;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunIdGenerator;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Crypto\RandomKeyGenerator;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Crypto\SodiumCipher;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run\RandomRunIdGenerator;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Runtime\ComposerPackageVersion;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Runtime\PhpRuntimeRequirements;
use Psr\Clock\ClockInterface;
use Symfony\Component\Console\Application;
use Symfony\Component\Clock\NativeClock;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface as ContractsEventDispatcherInterface;

use function Symfony\Component\DependencyInjection\Loader\Configurator\tagged_iterator;

/*
 * Services of the tool. Everything under src/ is autowired and autoconfigured, except the build side
 * (the container is compiled by it, never served by it), the metadata attributes, and classes that are
 * values rather than services: those are created by generated factories.
 */
return static function (ContainerConfigurator $container, ContainerBuilder $builder): void {
    $builder->registerForAutoconfiguration(Command::class)->addTag('key_rotator.console_command');

    $services = $container->services()
        ->defaults()
        ->autowire()
        ->autoconfigure()
        ->private();

    $services->load('Hryvinskyi\\EncryptionKeyRotator\\', '../src/')
        ->exclude([
            '../src/DependencyInjection/',
            '../src/Kernel/',
            '../src/Application/Requirements/RequirementsReport.php',
            '../src/Domain/Key/{Key,KeySlot,KeyRing}.php',
            '../src/Domain/Crypto/{Ciphertext,Plaintext}.php',
            '../src/Domain/Run/{RunId,RotationRun,ScanSummary}.php',
            '../src/Application/Model/{MagentoRoot,DatabaseSettings,ColumnRef,ScanScope,RowKey,ColumnCandidate}.php',
            '../src/Application/Model/{RunningProcess,StoredValue,Reencryption,Conflict,WriteResult,JournalEntry}.php',
            '../src/Application/Model/{SystemValue,SystemValueChange,ProbeSettings,ProbeOutcome,CacheCleanOutcome}.php',
        ]);

    $services->alias(RuntimeRequirements::class, PhpRuntimeRequirements::class);
    $services->alias(PackageVersion::class, ComposerPackageVersion::class);
    $services->alias(Cipher::class, SodiumCipher::class);
    $services->alias(KeyGenerator::class, RandomKeyGenerator::class);
    $services->alias(RunIdGenerator::class, RandomRunIdGenerator::class);

    // One system clock for the whole tool, read through the PSR clock; waiting goes through the pause port.
    $services->set(NativeClock::class);
    $services->alias(ClockInterface::class, NativeClock::class);

    $services->set(EventDispatcher::class);
    $services->alias(EventDispatcherInterface::class, EventDispatcher::class);
    $services->alias(ContractsEventDispatcherInterface::class, EventDispatcher::class);

    $services->set(ConsoleApplication::class)
        ->arg('$commands', tagged_iterator('key_rotator.console_command'));
    $services->alias(Application::class, ConsoleApplication::class)->public();

    // Each area of the tool keeps its own wiring in config/services/<area>.php: the port aliases of its adapters,
    // and `$services->remove(...)` for the value objects it adds, which the load above registered as services.
    $container->import(__DIR__ . '/services/*.php', null, 'not_found');
};
