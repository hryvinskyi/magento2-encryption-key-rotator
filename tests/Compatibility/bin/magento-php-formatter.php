<?php

declare(strict_types=1);

/*
 * Renders a configuration file the way the store's own deployment configuration writer does, with the
 * formatter of the installed code base MAGENTO_ROOT names: the file given as the only argument is
 * evaluated and its array printed as the formatter formats it, on stdout, without comments.
 *
 * The store's class is named as a string: this package does not depend on it, it comes from the
 * autoloader of MAGENTO_ROOT at run time.
 */

ini_set('display_errors', 'stderr');

$root = getenv('MAGENTO_ROOT');
if (!is_string($root) || $root === '' || !is_file($root . '/vendor/autoload.php')) {
    fwrite(STDERR, "MAGENTO_ROOT does not name an installed code base.\n");
    exit(2);
}
$file = $argv[1] ?? '';
if (!is_file($file)) {
    fwrite(STDERR, "Name the configuration file to render.\n");
    exit(2);
}

require $root . '/vendor/autoload.php';

$class = 'Magento\\Framework\\App\\DeploymentConfig\\Writer\\PhpFormatter';
if (!class_exists($class)) {
    fwrite(STDERR, sprintf("Class %s is not available in this code base.\n", $class));
    exit(4);
}
$data = include $file;
if (!is_array($data)) {
    fwrite(STDERR, "The configuration file does not return an array.\n");
    exit(3);
}

$formatter = new $class();
$format = [$formatter, 'format'];
if (!is_callable($format)) {
    fwrite(STDERR, sprintf("%s has no method format().\n", $class));
    exit(4);
}
$rendered = $format($data);
if (!is_string($rendered)) {
    fwrite(STDERR, "The formatter returned no text.\n");
    exit(4);
}
echo $rendered;
