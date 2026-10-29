<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Run;

/**
 * Where a rotation stands.
 *
 * The forward path is started → key_pending → key_added → web_confirmed → reencrypted → retire_pending
 * → retired → purged. A rollback can start from every state but rolled_back and purged, and goes
 * rolling_back → rolled_back → purged.
 *
 * key_pending, retire_pending and rolling_back are recorded before the key ring write they announce, so
 * a crash between that write and the next save can be resumed: they, and reencrypted (a second
 * re-encryption pass), can be recorded again while they are the state.
 */
enum RunState: string
{
    case Started = 'started';
    case KeyPending = 'key_pending';
    case KeyAdded = 'key_added';
    case WebConfirmed = 'web_confirmed';
    case Reencrypted = 'reencrypted';
    case RetirePending = 'retire_pending';
    case Retired = 'retired';
    case RollingBack = 'rolling_back';
    case RolledBack = 'rolled_back';
    case Purged = 'purged';

    /**
     * Whether a run in this state may record that one next.
     */
    public function allows(self $next): bool
    {
        return in_array($next, $this->successors(), true);
    }

    /**
     * An unfinished run: one a store holds as the active run of its Magento root. A rolled-back or
     * purged run is finished; a retired run is not, until it is purged.
     */
    public function isActive(): bool
    {
        return $this !== self::RolledBack && $this !== self::Purged;
    }

    /**
     * @return list<self> the states a run in this state may record next
     */
    private function successors(): array
    {
        return match ($this) {
            self::Started => [self::KeyPending, self::RollingBack],
            self::KeyPending => [self::KeyPending, self::KeyAdded, self::RollingBack],
            self::KeyAdded => [self::WebConfirmed, self::RollingBack],
            self::WebConfirmed => [self::Reencrypted, self::RollingBack],
            self::Reencrypted => [self::Reencrypted, self::RetirePending, self::RollingBack],
            self::RetirePending => [self::RetirePending, self::Retired, self::RollingBack],
            self::Retired => [self::Purged, self::RollingBack],
            self::RollingBack => [self::RollingBack, self::RolledBack],
            self::RolledBack => [self::Purged],
            self::Purged => [],
        };
    }
}
