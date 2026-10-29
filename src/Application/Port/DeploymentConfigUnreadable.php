<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

/**
 * The deployment configuration could not be read: the file is missing, does not return an array, or
 * lacks a section the tool needs. The message names the file and the section, never a value.
 */
final class DeploymentConfigUnreadable extends \RuntimeException {}
