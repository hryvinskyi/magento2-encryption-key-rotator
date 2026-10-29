<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Cli\Presenter;

use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate\RotateResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate\RotateStatus;
use Hryvinskyi\EncryptionKeyRotator\Cli\ExitCode;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Writes what a rotation did and gives its exit code.
 *
 * A dry run writes the plan. Every other result ends the same way, so the operator always finds it at
 * the bottom: the run id, what was written, what remains under the old keys, the note on bearer tokens,
 * and the exact next commands (status, retire, rollback, and rotate again when the run waits).
 */
final class RotatePresenter
{
    public const BEARER_TOKEN_NOTE = 'Bearer tokens (REST and GraphQL) signed before the new key was appended stop working: the store signs and verifies them with the last key of the ring only, so their holders have to sign in again. OAuth integration tokens keep working.';

    public function __construct(
        private readonly ReportSections $sections,
    ) {}

    /**
     * @param string $storeOptions the store options to repeat in the next commands
     * @param string $probeOptions the store and probe options to repeat in the next commands
     */
    public function present(RotateResult $result, OutputInterface $output, string $storeOptions, string $probeOptions): int
    {
        if ($result->status() === RotateStatus::DryRun) {
            $this->plan($result, $output);

            return $result->refusals() === [] ? ExitCode::DONE : ExitCode::REFUSED;
        }

        $output->writeln(sprintf('Rotation: <info>%s</info>', $result->status()->value));
        $this->sections->refusals($output, $result->refusals());
        $this->sections->workers($output, $result->workers());
        $this->sections->probe($output, $result->probe());
        $this->sections->reencryption($output, 'Database', $result->reencryption());
        $this->sections->systemPaths($output, $result->rewrittenSystemPaths());
        $this->sections->cacheClean($output, $result->cacheClean());
        if ($result->scan() !== null) {
            $output->writeln('Values per key index now:');
            $this->sections->scan($output, $result->scan());
        }
        $this->closing($result, $output, $storeOptions, $probeOptions);

        return match ($result->status()) {
            RotateStatus::Reencrypted, RotateStatus::DryRun => ExitCode::DONE,
            RotateStatus::AwaitingWebTier => ExitCode::WAITING,
            RotateStatus::Refused => ExitCode::REFUSED,
        };
    }

    /**
     * The plan of a dry run, also shown before the operator confirms a new rotation.
     */
    public function plan(RotateResult $result, OutputInterface $output): void
    {
        $output->writeln('<info>Plan</info> (nothing was written):');
        $output->writeln(sprintf('  key ring %s; the new key becomes index %s', $result->ringFingerprint() ?? 'unknown', $result->newIndex() === null ? '?' : (string) $result->newIndex()));
        $output->writeln(sprintf('  values under key indices %s move onto it', implode(', ', $result->sourceIndices())));
        if ($result->scan() !== null) {
            $this->sections->scan($output, $result->scan());
            $committed = $this->sections->committedOn($result->scan(), $result->sourceIndices());
            $output->writeln(sprintf(
                '  %d value(s) would move; %d in app/etc/config.php stay until it is redeployed with them re-encrypted.',
                $result->scan()->verifiedOnAny($result->sourceIndices()) - $committed,
                $committed,
            ));
        }
        $this->sections->refusals($output, $result->refusals());
        $this->sections->workers($output, $result->workers());
    }

    private function closing(RotateResult $result, OutputInterface $output, string $storeOptions, string $probeOptions): void
    {
        $output->writeln('');
        $runId = $result->runId();
        if ($runId === null) {
            $output->writeln('No run was started; nothing was written.');
            $this->sections->nextCommands($output, [
                sprintf('key-rotator rotate %s   once the refusal above is resolved', $probeOptions),
            ]);

            return;
        }

        $id = $runId->toString();
        $written = $result->reencryption()?->appliedTotal() ?? 0;
        $output->writeln(sprintf('Run: <info>%s</info> (%s)', $id, $result->state()->value ?? 'unknown state'));
        $output->writeln(sprintf(
            'Written: %s; %d database value(s) and %d app/etc/env.php value(s) re-encrypted.',
            $result->bearerTokensInvalidated() ? 'the new key is in app/etc/env.php' : 'the key ring is unchanged',
            $written,
            count($result->rewrittenSystemPaths()),
        ));
        $output->writeln(sprintf('Remains: %s', $this->remaining($result)));
        $output->writeln($result->bearerTokensInvalidated()
            ? 'Note: ' . self::BEARER_TOKEN_NOTE
            : 'Note: bearer tokens are unaffected while the key ring does not hold the new key.');

        $next = [sprintf('key-rotator status %s   shows run %s and what it allows next', $storeOptions, $id)];
        if ($result->status() !== RotateStatus::Reencrypted) {
            $next[] = sprintf('key-rotator rotate %s   resumes run %s once the cause above is resolved (reload PHP-FPM when the web tier waits)', $probeOptions, $id);
        }
        $next[] = sprintf('key-rotator retire %s   retires the old keys of run %s once nothing remains on them (wait until links and tokens they encrypted have expired)', $probeOptions, $id);
        $next[] = sprintf('key-rotator rollback %s   undoes run %s', $probeOptions, $id);
        $this->sections->nextCommands($output, $next);
    }

    private function remaining(RotateResult $result): string
    {
        $scan = $result->scan();
        if ($scan === null) {
            return 'not scanned yet; the values under the old keys have not moved.';
        }
        $committed = $this->sections->committedOn($scan, $result->sourceIndices());

        return sprintf(
            '%d value(s) still under key indices %s in the database and app/etc/env.php; %d in app/etc/config.php (redeploy it with them re-encrypted before retire); %d value(s) no key of the ring decrypts (never touched).',
            $scan->verifiedOnAny($result->sourceIndices()) - $committed,
            implode(', ', $result->sourceIndices()),
            $committed,
            $scan->summary()->undecryptable(),
        );
    }
}
