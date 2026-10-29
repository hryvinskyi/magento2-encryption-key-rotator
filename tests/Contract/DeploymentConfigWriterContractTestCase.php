<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Contract;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueChange;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueSource;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigWriter;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\StaleDeploymentConfig;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Ciphertext;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRingParser;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeyFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeyRingFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeySlotFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use PHPUnit\Framework\TestCase;

/**
 * What every implementation of {@see DeploymentConfigWriter} must do, read back through the
 * {@see DeploymentConfigReader} of the same implementation, so the in-memory double the use case tests
 * run against and the adapter that writes `app/etc/env.php` behave alike.
 *
 * Each implementation gets one concrete subclass. A subclass for the in-memory double lives under
 * `tests/Contract/` and runs with the unit tests; a subclass for an adapter that needs a file tree, a
 * subprocess or a server lives under `tests/Integration/Contract/`, so it runs in the integration suite.
 */
abstract class DeploymentConfigWriterContractTestCase extends TestCase
{
    private const PAYMENT = ['payment', 'gateway', 'api_secret'];
    private const CARRIER = ['carriers', 'courier', 'password'];

    private string $ringBefore;
    private Ciphertext $payment;
    private Ciphertext $carrier;

    /**
     * Gives the store a deployment configuration whose `crypt/key` is the ring and whose `system` section
     * holds the values at their paths.
     *
     * @param list<array{path: list<string>, value: string}> $systemValues
     */
    abstract protected function seed(string $cryptKey, array $systemValues): void;

    abstract protected function reader(): DeploymentConfigReader;

    abstract protected function writer(): DeploymentConfigWriter;

    protected function setUp(): void
    {
        $this->ringBefore = KeyMaterial::placeholder() . "\n" . KeyMaterial::rawKey() . "\n" . KeyMaterial::base64Key();
        $this->payment = $this->ciphertext(2, 'payment secret');
        $this->carrier = $this->ciphertext(1, 'carrier password');
        $this->seed($this->ringBefore, [
            ['path' => self::PAYMENT, 'value' => $this->payment->toString()],
            ['path' => self::CARRIER, 'value' => $this->carrier->toString()],
        ]);
    }

    public function testTheSeededConfigurationReadsBack(): void
    {
        self::assertSame($this->parse($this->ringBefore)->export(), $this->reader()->keyRing()->export());
        self::assertSame(
            ['carriers/courier/password' => $this->carrier->toString(), 'payment/gateway/api_secret' => $this->payment->toString()],
            $this->systemValues(),
        );
    }

    public function testAWrittenRingAndSystemValueReadBackExactly(): void
    {
        $before = $this->reader()->keyRing();
        $appended = $this->parse($this->ringBefore . "\n" . KeyMaterial::base64Key());
        $reencrypted = $this->ciphertext(3, 'payment secret under the new key');

        $this->writer()->write($appended, $before->fingerprint(), [new SystemValueChange(self::PAYMENT, $this->payment, $reencrypted)]);

        $read = $this->reader()->keyRing();
        self::assertSame($appended->export(), $read->export());
        self::assertSame($appended->fingerprint(), $read->fingerprint());
        self::assertSame(3, $read->activeIndex());
        self::assertSame(
            ['carriers/courier/password' => $this->carrier->toString(), 'payment/gateway/api_secret' => $reencrypted->toString()],
            $this->systemValues(),
        );
    }

    public function testARingWithRetiredSlotsReadsBackWithThem(): void
    {
        $before = $this->reader()->keyRing();
        $slots = $before->slots();
        $retired = $this->parse(KeyMaterial::placeholder() . "\n" . KeyMaterial::placeholder() . "\n" . $slots[2]->raw());

        $this->writer()->write($retired, $before->fingerprint(), []);

        $read = $this->reader()->keyRing();
        self::assertSame($retired->export(), $read->export());
        self::assertSame([], $read->usableOldIndices());
        self::assertTrue($read->slots()[1]->isRetired());
    }

    public function testAStaleExpectedRingWritesNothing(): void
    {
        $appended = $this->parse($this->ringBefore . "\n" . KeyMaterial::base64Key());
        $stale = $this->parse(KeyMaterial::rawKey())->fingerprint();

        try {
            $this->writer()->write($appended, $stale, [new SystemValueChange(self::PAYMENT, $this->payment, $this->ciphertext(3, 'x'))]);
            self::fail('A write with a stale expected ring was applied.');
        } catch (StaleDeploymentConfig $refused) {
            self::assertStringNotContainsString($appended->export(), $refused->getMessage());
        }

        $this->assertNothingWasWritten();
    }

    public function testAStaleExpectedSystemValueWritesNothing(): void
    {
        $before = $this->reader()->keyRing();
        $appended = $this->parse($this->ringBefore . "\n" . KeyMaterial::base64Key());
        $notThePaymentValue = $this->ciphertext(2, 'what someone else wrote');

        try {
            $this->writer()->write($appended, $before->fingerprint(), [
                new SystemValueChange(self::CARRIER, $this->carrier, $this->ciphertext(3, 'carrier under the new key')),
                new SystemValueChange(self::PAYMENT, $notThePaymentValue, $this->ciphertext(3, 'payment under the new key')),
            ]);
            self::fail('A write with a stale expected system value was applied.');
        } catch (StaleDeploymentConfig) {
            $this->addToAssertionCount(1);
        }

        $this->assertNothingWasWritten();
    }

    public function testAChangeAtAPathThatHoldsNoValueWritesNothing(): void
    {
        $before = $this->reader()->keyRing();
        $appended = $this->parse($this->ringBefore . "\n" . KeyMaterial::base64Key());

        try {
            $this->writer()->write($appended, $before->fingerprint(), [
                new SystemValueChange(['payment', 'gone', 'secret'], $this->payment, $this->ciphertext(3, 'nowhere')),
            ]);
            self::fail('A change at an empty path was applied.');
        } catch (StaleDeploymentConfig) {
            $this->addToAssertionCount(1);
        }

        $this->assertNothingWasWritten();
    }

    private function assertNothingWasWritten(): void
    {
        self::assertSame($this->parse($this->ringBefore)->export(), $this->reader()->keyRing()->export());
        self::assertSame(
            ['carriers/courier/password' => $this->carrier->toString(), 'payment/gateway/api_secret' => $this->payment->toString()],
            $this->systemValues(),
        );
    }

    /**
     * @return array<string, string> path => ciphertext, sorted by path
     */
    private function systemValues(): array
    {
        $values = [];
        foreach ($this->reader()->systemValues() as $value) {
            self::assertSame(SystemValueSource::Env, $value->source());
            $values[$value->pathString()] = $value->ciphertext()->toString();
        }
        ksort($values);

        return $values;
    }

    private function parse(string $cryptKey): KeyRing
    {
        $keys = new DirectKeyFactory();

        return (new KeyRingParser(new DirectKeySlotFactory(), new DirectKeyRingFactory($keys)))->parse($cryptKey);
    }

    /**
     * A value with the shape of a stored ciphertext; the contract compares values and never decrypts.
     */
    private function ciphertext(int $keyIndex, string $seed): Ciphertext
    {
        return new Ciphertext($keyIndex, 3, base64_encode(str_pad($seed, 48, '.')));
    }
}
