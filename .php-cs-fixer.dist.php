<?php

declare(strict_types=1);

use PhpCsFixer\Config;
use PhpCsFixer\Finder;

$finder = Finder::create()
    ->in([__DIR__ . '/src', __DIR__ . '/tests', __DIR__ . '/config', __DIR__ . '/tools'])
    ->append([__DIR__ . '/bin/key-rotator', __DIR__ . '/build/compile.php', __FILE__]);

return (new Config())
    ->setRiskyAllowed(true)
    ->setRules([
        '@PER-CS2.0' => true,
        'declare_strict_types' => true,
        'strict_param' => true,
        'no_unused_imports' => true,
    ])
    ->setFinder($finder);
