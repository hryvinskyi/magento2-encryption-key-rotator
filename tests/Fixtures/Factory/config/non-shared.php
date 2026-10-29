<?php

declare(strict_types=1);

use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return static function (ContainerConfigurator $container): void {

    $services = $container->services()->defaults()->autowire()->autoconfigure();
    $services->load('Hryvinskyi\\EncryptionKeyRotator\\Tests\\Fixtures\\Factory\\NonShared\\', '../NonShared/')
        ->exclude(['../NonShared/Document.php']);
    $services->set('Hryvinskyi\\EncryptionKeyRotator\\Tests\\Fixtures\\Factory\\NonShared\\Stamp')->share(false);
};
