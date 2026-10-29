# Magento 2 encryption key rotator

`key-rotator.phar` rotates the encryption key of a Magento 2 store and can undo the rotation at every step.

It does not boot Magento. It reads `app/etc/env.php` itself and talks to the database through PDO, so it keeps
working, rollback included, when Magento cannot boot. Every value it rewrites goes through a compare-and-swap and is
recorded in a journal. The keys it replaces are kept until you purge the run. No value is moved onto a new key until
PHP-FPM has been seen holding that key.

## Requirements

- PHP 8.1 or later on the command line, with `sodium` and `pdo_mysql`. Tested on PHP 8.1 and 8.3.
- MariaDB 10.6+ or MySQL 8.0+.
- Magento 2.4 with cipher version 3 ciphertexts (ChaCha20-Poly1305, what current 2.4 releases write). Values
  written with an older cipher are reported and never touched.
- The user that owns `app/etc/env.php`.
- `ps` on the host where the store's cron jobs and queue consumers run, for the worker check.

## Install

Download the phar and its checksum from the
[latest release](https://github.com/hryvinskyi/magento2-encryption-key-rotator/releases/latest):

```sh
curl -fLO https://github.com/hryvinskyi/magento2-encryption-key-rotator/releases/latest/download/key-rotator.phar
curl -fLO https://github.com/hryvinskyi/magento2-encryption-key-rotator/releases/latest/download/key-rotator.phar.sha256
shasum -a 256 -c key-rotator.phar.sha256
php key-rotator.phar about
```

Keep the phar outside the document root.

## Quick start

Run these from the Magento root, or pass `--magento-root=/path/to/magento`.

```sh
# 1. What is encrypted, and under which key (read-only)
php key-rotator.phar scan

# 2. Preflight, the baseline web probe and the plan; nothing is written
php key-rotator.phar rotate --dry-run --probe-fcgi=unix:///run/php/php-fpm.sock

# 3. Stop cron and the queue consumers, then rotate
php key-rotator.phar rotate --probe-fcgi=unix:///run/php/php-fpm.sock

# 4. Where the run stands, and what it allows next
php key-rotator.phar status

# 5. Days later, once links and tokens encrypted with the old key have expired
php key-rotator.phar retire --probe-fcgi=unix:///run/php/php-fpm.sock

# 6. When the store has run on the new key alone for a while: delete the kept keys and the journal
php key-rotator.phar purge
```

At any point before `purge`:

```sh
php key-rotator.phar rollback --probe-fcgi=unix:///run/php/php-fpm.sock
```

## Commands

| Command | What it does |
|---|---|
| `scan` | Counts the encrypted values per key index in the database, `app/etc/env.php` and `app/etc/config.php`: verified, retired key, unknown key, unsupported cipher, authentication failed. Read-only. `--format=json` gives a stable report. |
| `rotate` | Appends a new key, waits until PHP-FPM holds the new key ring, then re-encrypts every value under the old usable keys in the database and in `env.php`, and cleans the configuration cache. Run it again and an unfinished run resumes where it stopped. |
| `status` | The current or last run, its history and waived checks, the key ring `env.php` holds now, and the commands allowed next. Read-only. |
| `retire` | Re-encrypts values written under the old keys since the rotation, then replaces the old keys with placeholders. It refuses while anything still needs them. |
| `rollback` | Undoes an unfinished or retired run. Every value gets its bytes from before the run back, and values the store wrote under the new key are moved back onto the old one. Then the new key slot is removed and the key ring is as it was before the run. Run it again to finish an interrupted rollback. |
| `purge` | Deletes the journal and the kept keys of a retired or rolled-back run. After a purge the run can no longer be rolled back. |

`php key-rotator.phar help <command>` lists every option.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Done. |
| 2 | Waiting for the web tier: reload PHP-FPM and run the same command again. |
| 3 | Refused. Nothing was written past the check, and the message says why. |
| 1 | Unexpected error. |

## How a rotation works

A Magento key ring is the whitespace-separated list in `env.php` at `crypt/key`. The last entry is the active key,
and every ciphertext starts with the index of the key that encrypted it (`1:3:…`). The tool keeps these indices
stable. A new key is appended, and a retired key is replaced by a 32-character `invalid…` placeholder, so it keeps
its position.

1. **rotate**
   - Preflight checks:
     - `env.php` holds only literal data and is writable;
     - the tool runs as its owner;
     - the state directory is safe;
     - no other run is unfinished;
     - no store process is running;
     - the baseline web probe answers.
   - The new key is saved in the run directory first. The run records which key ring it is about to write, and only
     then is `env.php` written. The write is a compare-and-swap on the fingerprint of the ring the run expects to
     find.
   - The web probe asks PHP-FPM until the pool holds the new ring. Only then do values move. They move in batches,
     and each value is decrypted again before it is written.
2. **retire**
   - Values written under the old keys since the rotation are re-encrypted first.
   - The tool refuses while any value in the database, in `env.php` or in `app/etc/config.php` is still under an old
     key.
   - It keeps the old keys and the placeholders in the run directory, then writes `env.php` and probes again.
3. **rollback**
   - Restores retired keys, then waits until PHP-FPM holds them again.
   - Writes back the old bytes from the journal.
   - Moves every value the store wrote under the new key back onto the old one.
   - Removes the new slot. It removes a slot only when the index and the key both match, never by position.
4. **purge**
   - Checks, with the kept keys, that nothing on the indices that become unreadable still decrypts, then deletes
     the journal rows and the run directory.

Every step that writes first re-reads `env.php`. If the key ring there is not the one the run recorded (the admin
Encryption Key page, a deploy, another process), the step stops with exit code 3 and names both fingerprints. A
crash at any point is resumed by running the same command again.

### What it never does

- Rewrite a value that changed since it was read. Every UPDATE compares the exact old bytes, in the same
  transaction as its journal row.
- Touch a value it cannot decrypt (unknown key, retired key, unsupported cipher, failed authentication). It only
  reports it.
- Remove or retire a key that a stored value still uses, or that PHP-FPM may still need.
- Print, log or journal a key or a plaintext. Keys are shown as fingerprints: the first 16 hex characters of the
  SHA-256 of the key bytes.
- Write `app/etc/config.php`. That file is tracked and deployed: re-encrypt its values in your repository and
  deploy it before `retire`. When rolling back after such a deploy, deploy it again under the old key first.
- Rewrite a ciphertext embedded in a larger value (JSON, a serialised array). It counts them, and `retire` needs
  `--accept-embedded` to go on.
- Rewrite a ciphertext in a table without a primary or unique key. Its rows cannot be addressed, so the value blocks
  `retire` and `rollback` until you give the table a key or move the value by hand.

## The web probe

Opcache can keep an old copy of `env.php` in PHP-FPM, and the tool cannot see that from the command line. So it asks
the pool itself. It drops a one-off script with a random token and asks PHP-FPM to run it, and the script answers
with the fingerprint of the key ring the pool sees. The script is deleted right afterwards. Old probe files left by a
killed run are swept before the next one.

- `--probe-fcgi=unix:///run/php/php-fpm.sock` (or `tcp://127.0.0.1:9000`) talks FastCGI straight to the FPM socket.
  The script lives in the state directory, outside the document root. Use this one: a stock Magento nginx
  configuration runs only its entry points (`index.php`, `static.php`, …) and answers 403 to any other `.php`.
- `--probe-url=https://127.0.0.1` goes over HTTP to a script in the document root. It only works where the web server
  runs any `.php` file, and only to loopback or private addresses. `--probe-host` sets the `Host` header and
  `--insecure` skips TLS verification.
- `--skip-web-probe` skips the probe. The run records it. Use it only if you reload PHP-FPM by hand after every key
  ring change.

`rotate`, `retire` and `rollback` need one of the three. If the pool does not match within `--probe-wait` seconds
(120 by default), the command exits with 2. Reload PHP-FPM and run it again.

## The state directory

`--state-dir`, by default `<magento-root>/var/encryption-key-rotation`, holds one directory per run:
- the backup of `env.php`;
- the keys the run added or replaced;
- the run record.

Rollback is possible only while this directory exists. Keep it on persistent storage, and pass the same
`--state-dir` to every command of a run.

The directory holds key material, so the tool refuses to use it unless:
- it is not a symlink and belongs to the user running the tool;
- neither it nor its parent is writable by group or others (a sticky parent such as `/tmp` is accepted);
- nothing inside it is a symlink or belongs to another user.

On a store whose `var/` is group-writable for the web server, pass a `--state-dir` outside the document root that
only you can write and that PHP-FPM can traverse (needed for the FastCGI probe; the tool makes it `0711`). Run
directories are `0700` and files `0600`. On release-style deploys, keep it outside the release directory.

Zeroing files before deleting them is best effort on journaling, copy-on-write and SSD storage.

## Before you rotate a production store

- Take a database backup.
- **Stop cron and the queue consumers** for `rotate`, `retire` and `rollback`. A process that started before a key
  ring change still holds the old ring. The tool refuses while it sees one (`ps`, and `cron_schedule` jobs running in
  the last 15 minutes). `--ignore-workers` overrides this, and the run records it.
- Keep admins away from **System > Encryption Key** and **Cache Management** until the run is retired. A PHP-FPM
  worker with an old copy of `env.php` can write the old key ring back.
- If a deploy pipeline or your hosting provider rewrites `env.php` from its own copy, give them the file the tool
  wrote after every step that changes the key ring, before the next deploy. After that deploy, `status` warns if the
  copy they put back is not the one the run wrote.
- **Bearer tokens** for REST and GraphQL stop working as soon as the new key is appended: Magento signs and verifies
  them with the last key only. OAuth integration tokens keep working.
- Wait several days between `rotate` and `retire`. Payment links and e-mailed tokens encrypted with the old key keep
  working until then.
- Credentials that may have leaked with the old key, such as payment provider API keys and integration passwords,
  have to be replaced at their provider. Re-encrypting them does not make them secret again.
- Keyed hashes that modules store change with the active key, for example Magento's indexer configuration hash. Plan
  a full reindex after the next `setup:upgrade`.

## One run per store

A store has at most one unfinished run, whatever state directory each command is given. The run claims the store
in the table `<prefix>encryption_key_rotation_run` and keeps the claim until it is purged. A rolled-back run
therefore has to be purged before the next rotation. Old values are journaled in
`<prefix>encryption_key_rotation_journal`, whose rows `purge` deletes. Both tables honour `db/table_prefix`.

## Building from source

```sh
composer install
composer check                 # PHPStan level 10, Deptrac, php-cs-fixer, unit and contract tests
composer test:integration      # PHP 8.1 and 8.3 × MariaDB and MySQL, in Docker
MAGENTO_ROOT=/path/to/magento composer test:compat   # against Magento's own Encryptor
composer build                 # build/key-rotator.phar (Box needs PHP 8.2+ on the build host), then a smoke run
```

For a release build, install with the release's version so that `key-rotator --version` reports it:
`COMPOSER_ROOT_VERSION=1.2.3 composer install`, then `COMPOSER_ROOT_VERSION=1.2.3 composer build`.

## Licence

MIT.
