<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Cli\Option;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\InvalidMagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\InvalidValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\MagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\MagentoRootFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettingsFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanScope;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanScopeFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Scan\ScanEncryptedData;
use Hryvinskyi\EncryptionKeyRotator\Cli\OptionRefused;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;

/**
 * The options several commands share, defined and read in one place:
 * - the store options every command takes: `--magento-root` (the current directory by default),
 *   `--state-dir` (`<Magento root>/var/encryption-key-rotation` by default) and `--allow-other-user`;
 * - the probe options of the commands that change the key ring: `--probe-fcgi`, `--probe-url`,
 *   `--probe-host`, `--docroot`, `--probe-wait`, `--insecure` and `--skip-web-probe`;
 * - the scan options of the read-only scan: `--exclude` and `--batch-size`; a writing command takes
 *   `--batch-size` only, since it always covers every column;
 * - `--ignore-workers` and `--yes`.
 *
 * A relative path is taken relative to the current directory. A value that cannot be used is refused
 * with the option's name, before anything is written.
 */
final class CommandOptions
{
    public const MAGENTO_ROOT = 'magento-root';
    public const STATE_DIR = 'state-dir';
    public const ALLOW_OTHER_USER = 'allow-other-user';
    public const PROBE_FCGI = 'probe-fcgi';
    public const PROBE_URL = 'probe-url';
    public const PROBE_HOST = 'probe-host';
    public const DOCROOT = 'docroot';
    public const PROBE_WAIT = 'probe-wait';
    public const INSECURE = 'insecure';
    public const SKIP_WEB_PROBE = 'skip-web-probe';
    public const IGNORE_WORKERS = 'ignore-workers';
    public const YES = 'yes';
    public const EXCLUDE = 'exclude';
    public const BATCH_SIZE = 'batch-size';

    public const DEFAULT_STATE_DIR = 'var/encryption-key-rotation';
    public const DEFAULT_PROBE_WAIT = 120;

    public function __construct(
        private readonly MagentoRootFactory $roots,
        private readonly ProbeSettingsFactory $probeSettings,
        private readonly ScanScopeFactory $scopes,
    ) {}

    public function addStoreOptions(Command $command): void
    {
        $command
            ->addOption(self::MAGENTO_ROOT, null, InputOption::VALUE_REQUIRED, 'The Magento root (the directory holding app/etc/env.php); the current directory by default')
            ->addOption(self::STATE_DIR, null, InputOption::VALUE_REQUIRED, 'Where runs are kept, outside the document root and outside a release a deploy replaces; <magento-root>/' . self::DEFAULT_STATE_DIR . ' by default')
            ->addOption(self::ALLOW_OTHER_USER, null, InputOption::VALUE_NONE, 'Run although the tool runs as another user than the owner of app/etc/env.php (recorded in the run)');
    }

    public function addProbeOptions(Command $command): void
    {
        $command
            ->addOption(self::PROBE_FCGI, null, InputOption::VALUE_REQUIRED, 'Probe the web tier over FastCGI, straight to the PHP-FPM socket: unix:///run/php/php-fpm.sock or tcp://127.0.0.1:9000 (works behind a stock Magento nginx)')
            ->addOption(self::PROBE_URL, null, InputOption::VALUE_REQUIRED, 'Probe the web tier over HTTP: the base URL of a server that executes any .php file in the document root (a loopback or private address)')
            ->addOption(self::PROBE_HOST, null, InputOption::VALUE_REQUIRED, 'The host name the HTTP probe asks for, when it differs from the URL\'s')
            ->addOption(self::DOCROOT, null, InputOption::VALUE_REQUIRED, 'The document root relative to the Magento root', ProbeSettings::DEFAULT_DOCROOT)
            ->addOption(self::PROBE_WAIT, null, InputOption::VALUE_REQUIRED, 'Seconds to keep asking the web tier before the run waits', (string) self::DEFAULT_PROBE_WAIT)
            ->addOption(self::INSECURE, null, InputOption::VALUE_NONE, 'Do not verify TLS certificates of the HTTP probe')
            ->addOption(self::SKIP_WEB_PROBE, null, InputOption::VALUE_NONE, 'Do not probe the web tier (recorded in the run); only when PHP-FPM is reloaded by hand after every key ring change');
    }

    public function addScanOptions(Command $command): void
    {
        $command->addOption(self::EXCLUDE, null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Leave out a table or a table.column (* is a wildcard); repeatable');
        $this->addBatchSizeOption($command);
    }

    public function addBatchSizeOption(Command $command): void
    {
        $command->addOption(self::BATCH_SIZE, null, InputOption::VALUE_REQUIRED, 'How many values are read and written at once', (string) ScanEncryptedData::DEFAULT_BATCH_SIZE);
    }

    public function addIgnoreWorkersOption(Command $command): void
    {
        $command->addOption(self::IGNORE_WORKERS, null, InputOption::VALUE_NONE, 'Go on although store commands or cron jobs that may hold an earlier key ring are running (recorded in the run)');
    }

    public function addConfirmationOption(Command $command): void
    {
        $command->addOption(self::YES, 'y', InputOption::VALUE_NONE, 'Do not ask for confirmation');
    }

    public function definesStoreOptions(Command $command): bool
    {
        return $command->getDefinition()->hasOption(self::MAGENTO_ROOT);
    }

    public function definesProbeOptions(Command $command): bool
    {
        return $command->getDefinition()->hasOption(self::PROBE_WAIT);
    }

    /**
     * @throws OptionRefused when the path is not a Magento root, or the current directory is unknown
     */
    public function magentoRoot(InputInterface $input): MagentoRoot
    {
        $given = $this->string($input, self::MAGENTO_ROOT);
        try {
            return $this->roots->create($this->absolute($given ?? '.'));
        } catch (InvalidMagentoRoot $invalid) {
            throw new OptionRefused(sprintf('--%s: %s', self::MAGENTO_ROOT, $invalid->getMessage()), 0, $invalid);
        }
    }

    /**
     * The state directory given, or the default one inside the root.
     *
     * @throws OptionRefused when the current directory is unknown
     */
    public function stateDirectory(InputInterface $input, MagentoRoot $root): string
    {
        $given = $this->string($input, self::STATE_DIR);

        return $given === null ? $root->file(self::DEFAULT_STATE_DIR) : rtrim($this->absolute($given), '/');
    }

    /**
     * The probe settings the options describe; none of the three ways to confirm the web tier is fine
     * here ({@see requireProbeChoice()} refuses it where a command needs one).
     *
     * @throws OptionRefused when a setting is malformed or contradicts another
     */
    public function probeSettings(InputInterface $input): ProbeSettings
    {
        $wait = $this->string($input, self::PROBE_WAIT) ?? (string) self::DEFAULT_PROBE_WAIT;
        if (preg_match('/^\d{1,6}$/D', $wait) !== 1) {
            throw new OptionRefused(sprintf('--%s takes a whole number of seconds; "%s" is not one.', self::PROBE_WAIT, $wait));
        }
        try {
            return $this->probeSettings->create(
                fastCgiAddress: $this->string($input, self::PROBE_FCGI),
                baseUrl: $this->string($input, self::PROBE_URL),
                hostHeader: $this->string($input, self::PROBE_HOST),
                docroot: $this->string($input, self::DOCROOT) ?? ProbeSettings::DEFAULT_DOCROOT,
                verifyTls: !$this->flag($input, self::INSECURE),
                waitSeconds: (int) $wait,
                skipped: $this->flag($input, self::SKIP_WEB_PROBE),
            );
        } catch (InvalidValue $invalid) {
            throw new OptionRefused('Probe options: ' . $invalid->getMessage(), 0, $invalid);
        }
    }

    /**
     * Refuses settings that name no way to confirm which key ring the web tier holds.
     *
     * @throws OptionRefused when neither transport is named and the probe is not skipped
     */
    public function requireProbeChoice(ProbeSettings $settings): void
    {
        if ($settings->transport() !== null || $settings->isSkipped()) {
            return;
        }

        throw new OptionRefused(implode("\n", [
            'This command changes the key ring, so it must confirm that the web tier (PHP-FPM) holds the ring it writes. Choose one of:',
            sprintf('  --%s=unix:///run/php/php-fpm.sock (or tcp://127.0.0.1:9000)  FastCGI straight to the PHP-FPM socket; works behind a stock Magento nginx.', self::PROBE_FCGI),
            sprintf('  --%s=http://127.0.0.1 [--%s=store.example.com]  HTTP, only where the web server executes any .php file in the document root.', self::PROBE_URL, self::PROBE_HOST),
            sprintf('  --%s  no probe (recorded in the run); then reload PHP-FPM yourself after every key ring change.', self::SKIP_WEB_PROBE),
            'Nothing was written.',
        ]));
    }

    /**
     * @throws OptionRefused when an exclusion pattern is malformed
     */
    public function scope(InputInterface $input): ScanScope
    {
        $given = $input->hasOption(self::EXCLUDE) ? $input->getOption(self::EXCLUDE) : [];
        $exclusions = array_values(array_filter(is_array($given) ? $given : [], static fn(mixed $pattern): bool => is_string($pattern) && $pattern !== ''));
        try {
            return $this->scopes->create($exclusions);
        } catch (InvalidValue $invalid) {
            throw new OptionRefused(sprintf('--%s: %s', self::EXCLUDE, $invalid->getMessage()), 0, $invalid);
        }
    }

    /**
     * @throws OptionRefused when the size is not a whole number of at least 1
     */
    public function batchSize(InputInterface $input): int
    {
        $size = $this->string($input, self::BATCH_SIZE) ?? (string) ScanEncryptedData::DEFAULT_BATCH_SIZE;
        if (preg_match('/^[1-9]\d{0,6}$/D', $size) !== 1) {
            throw new OptionRefused(sprintf('--%s takes a whole number of at least 1; "%s" is not one.', self::BATCH_SIZE, $size));
        }

        return (int) $size;
    }

    public function allowsOtherUser(InputInterface $input): bool
    {
        return $this->flag($input, self::ALLOW_OTHER_USER);
    }

    public function ignoresWorkers(InputInterface $input): bool
    {
        return $this->flag($input, self::IGNORE_WORKERS);
    }

    public function confirmedUpFront(InputInterface $input): bool
    {
        return $this->flag($input, self::YES);
    }

    /**
     * The store options, and the probe options when asked, as the operator gave them, for printing the
     * next command to run.
     */
    public function repeated(InputInterface $input, bool $withProbeOptions): string
    {
        $names = [self::STATE_DIR, self::ALLOW_OTHER_USER];
        if ($withProbeOptions) {
            $names = [...$names, self::PROBE_FCGI, self::PROBE_URL, self::PROBE_HOST, self::DOCROOT, self::INSECURE, self::SKIP_WEB_PROBE];
        }

        // The root is always named, so the printed command works from any directory.
        $parts = [sprintf('--%s=%s', self::MAGENTO_ROOT, escapeshellarg($this->absolute($this->string($input, self::MAGENTO_ROOT) ?? '.')))];
        foreach ($names as $name) {
            if (!$input->hasOption($name)) {
                continue;
            }
            $value = $input->getOption($name);
            if ($value === true) {
                $parts[] = '--' . $name;

                continue;
            }
            if (is_string($value) && $value !== '' && !($name === self::DOCROOT && $value === ProbeSettings::DEFAULT_DOCROOT)) {
                $parts[] = sprintf('--%s=%s', $name, escapeshellarg($name === self::STATE_DIR ? $this->absolute($value) : $value));
            }
        }

        return implode(' ', $parts);
    }

    private function string(InputInterface $input, string $name): ?string
    {
        if (!$input->hasOption($name)) {
            return null;
        }
        $value = $input->getOption($name);

        return is_string($value) && $value !== '' ? $value : null;
    }

    private function flag(InputInterface $input, string $name): bool
    {
        return $input->hasOption($name) && $input->getOption($name) === true;
    }

    /**
     * @throws OptionRefused when the path is relative and the current directory is unknown
     */
    private function absolute(string $path): string
    {
        if (str_starts_with($path, '/')) {
            return $path;
        }
        $cwd = getcwd();
        if ($cwd === false) {
            throw new OptionRefused(sprintf('The current directory cannot be read, so "%s" cannot be resolved; give an absolute path.', $path));
        }

        return $path === '.' ? $cwd : rtrim($cwd, '/') . '/' . $path;
    }
}
