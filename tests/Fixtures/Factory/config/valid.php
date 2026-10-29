<?php

declare(strict_types=1);

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return static function (ContainerConfigurator $container): void {
    $container->parameters()->set('fixture.separator', ' | ');

    $services = $container->services()->defaults()->autowire()->autoconfigure();
    $services->load('Hryvinskyi\\EncryptionKeyRotator\\Tests\\Fixtures\\Factory\\Valid\\', '../Valid/')
        ->exclude(['../Valid/Greeting.php', '../Valid/Farewell.php']);
    $services->alias('fixture.greeting_factory', 'Hryvinskyi\\EncryptionKeyRotator\\Tests\\Fixtures\\Factory\\Valid\\GreetingFactory')->public();
    $services->alias('fixture.farewell_factory', 'Hryvinskyi\\EncryptionKeyRotator\\Tests\\Fixtures\\Factory\\Valid\\FarewellFactory')->public();
};
