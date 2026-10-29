<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Domain\Key;

use Hryvinskyi\EncryptionKeyRotator\Domain\Key\InvalidKey;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\InvalidKeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\Key;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRingChangeRefused;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeySlot;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeyFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeyRingFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeySlotFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class KeyRingTest extends TestCase
{
    private DirectKeyFactory $keys;
    private DirectKeySlotFactory $slots;
    private DirectKeyRingFactory $rings;

    protected function setUp(): void
    {
        $this->keys = new DirectKeyFactory();
        $this->slots = new DirectKeySlotFactory();
        $this->rings = new DirectKeyRingFactory($this->keys);
    }

    public function testARingWithoutSlotsIsRefused(): void
    {
        $this->expectException(InvalidKeyRing::class);

        new KeyRing([], $this->keys);
    }

    public function testARingWithAGapInItsIndicesIsRefused(): void
    {
        $this->expectException(InvalidKeyRing::class);
        $this->expectExceptionMessage('position 1 holds slot 2');

        new KeyRing([new KeySlot(0, KeyMaterial::rawKey()), new KeySlot(2, KeyMaterial::rawKey())], $this->keys);
    }

    public function testARingWhoseSlotsAreOutOfOrderIsRefused(): void
    {
        $this->expectException(InvalidKeyRing::class);

        new KeyRing([new KeySlot(1, KeyMaterial::rawKey()), new KeySlot(0, KeyMaterial::rawKey())], $this->keys);
    }

    public function testARingWhoseActiveSlotIsRetiredIsRefused(): void
    {
        $this->expectException(InvalidKeyRing::class);

        new KeyRing([new KeySlot(0, KeyMaterial::rawKey()), new KeySlot(1, KeyMaterial::placeholder())], $this->keys);
    }

    public function testARingWithAnOldSlotThatIsNotAKeyIsRefusedWithoutNamingTheEntry(): void
    {
        try {
            new KeyRing([new KeySlot(0, 'broken-entry'), new KeySlot(1, KeyMaterial::rawKey())], $this->keys);
            self::fail('A ring with an unusable slot was accepted.');
        } catch (InvalidKey $refused) {
            self::assertStringContainsString('Key slot 0', $refused->getMessage());
            self::assertStringNotContainsString('broken-entry', $refused->getMessage());
        }
    }

    public function testTheUsableOldIndicesAreTheSlotsBelowTheActiveOneThatAreNotRetired(): void
    {
        $ring = $this->ring(KeyMaterial::rawKey(), KeyMaterial::placeholder(), KeyMaterial::base64Key(), KeyMaterial::rawKey());

        self::assertSame(3, $ring->activeIndex());
        self::assertSame([0, 2], $ring->usableOldIndices());
    }

    public function testASlotIsLookedUpByIndex(): void
    {
        $second = KeyMaterial::rawKey();
        $ring = $this->ring(KeyMaterial::rawKey(), $second);

        self::assertSame($second, $ring->slot(1)?->raw());
        self::assertNull($ring->slot(2));
        self::assertNull($ring->slot(-1));
        self::assertCount(2, $ring->slots());
    }

    public function testTheExportJoinsTheEntriesWithNewlinesAndTheFingerprintIsItsHash(): void
    {
        $entries = [KeyMaterial::placeholder(), KeyMaterial::rawKey(), KeyMaterial::base64Key()];

        $ring = $this->ring(...$entries);

        self::assertSame(implode("\n", $entries), $ring->export());
        self::assertSame(substr(hash('sha256', implode("\n", $entries)), 0, 16), $ring->fingerprint());
    }

    public function testAppendingAKeyMakesItTheActiveSlotAndKeepsEveryOtherIndex(): void
    {
        $placeholder = KeyMaterial::placeholder();
        $old = KeyMaterial::rawKey();
        $ring = $this->ring($placeholder, $old);
        $new = new Key(KeyMaterial::base64Key());

        $appended = $ring->appended($new, $this->slots, $this->rings);

        self::assertSame(2, $appended->activeIndex());
        self::assertTrue($appended->active($this->keys)->equals($new));
        self::assertSame([1], $appended->usableOldIndices());
        self::assertSame($placeholder . "\n" . $old . "\n" . $new->raw(), $appended->export());
        self::assertSame($placeholder . "\n" . $old, $ring->export(), 'The original ring is unchanged.');
    }

    public function testAppendingAKeyTheRingAlreadyHoldsIsRefused(): void
    {
        $old = KeyMaterial::rawKey();
        $ring = $this->ring($old, KeyMaterial::rawKey());

        $this->expectException(KeyRingChangeRefused::class);
        $this->expectExceptionMessage('slot 0');

        $ring->appended(new Key($old), $this->slots, $this->rings);
    }

    public function testAppendingAKeyTheRingHoldsInTheOtherEncodingIsRefused(): void
    {
        $active = KeyMaterial::rawKey();
        $ring = $this->ring(KeyMaterial::placeholder(), $active);

        $this->expectException(KeyRingChangeRefused::class);

        $ring->appended(new Key('base64' . base64_encode($active)), $this->slots, $this->rings);
    }

    public function testAppendingAKeyWhoseEntryReadsAsARetiredSlotIsRefused(): void
    {
        $ring = $this->ring(KeyMaterial::rawKey());

        $this->expectException(KeyRingChangeRefused::class);

        $ring->appended(new Key(KeyMaterial::placeholder()), $this->slots, $this->rings);
    }

    public function testAppendingBeyondTheHighestIndexACiphertextCanCarryIsRefused(): void
    {
        $entries = [];
        for ($index = 0; $index <= KeyRing::MAX_INDEX; $index++) {
            $entries[] = KeyMaterial::placeholder();
        }
        $entries[KeyRing::MAX_INDEX] = KeyMaterial::rawKey();
        $ring = $this->ring(...$entries);

        $this->expectException(KeyRingChangeRefused::class);

        $ring->appended(new Key(KeyMaterial::rawKey()), $this->slots, $this->rings);
    }

    public function testRetiringReplacesEachNamedSlotWithItsPlaceholderInPlace(): void
    {
        $active = KeyMaterial::base64Key();
        $ring = $this->ring(KeyMaterial::rawKey(), KeyMaterial::rawKey(), $active);
        $placeholders = [KeyMaterial::placeholder(), KeyMaterial::placeholder()];

        $retired = $ring->withRetired([1, 0], $placeholders, $this->slots, $this->rings);

        self::assertSame($placeholders[1] . "\n" . $placeholders[0] . "\n" . $active, $retired->export());
        self::assertSame(2, $retired->activeIndex());
        self::assertSame([], $retired->usableOldIndices());
        self::assertSame([0, 1], $ring->usableOldIndices(), 'The original ring is unchanged.');
    }

    /**
     * @return iterable<string, array{list<int>, list<string>, string}>
     */
    public static function refusedRetirements(): iterable
    {
        yield 'the active slot' => [[2], [KeyMaterial::placeholder()], 'active key'];
        yield 'an already retired slot' => [[0], [KeyMaterial::placeholder()], 'already retired'];
        yield 'a slot the ring does not have' => [[5], [KeyMaterial::placeholder()], 'no slot 5'];
        yield 'nothing' => [[], [], 'No slot'];
        yield 'the same slot twice' => [[1, 1], [KeyMaterial::placeholder(), KeyMaterial::placeholder()], 'more than once'];
        yield 'fewer placeholders than slots' => [[1], [], '1 placeholders; 0 were given'];
        yield 'more placeholders than slots' => [[1], [KeyMaterial::placeholder(), KeyMaterial::placeholder()], '2 were given'];
        yield 'a placeholder without the prefix' => [[1], [KeyMaterial::rawKey()], 'must start with "invalid"'];
        yield 'a placeholder one character short' => [[1], [substr(KeyMaterial::placeholder(), 0, 31)], 'exactly 32'];
        yield 'a placeholder one character long' => [[1], [KeyMaterial::placeholder() . 'x'], 'exactly 32'];
        yield 'a placeholder with whitespace' => [[1], ['invalid' . str_repeat('a', 12) . ' ' . str_repeat('b', 12)], 'without whitespace'];
    }

    /**
     * @param list<int>    $indices
     * @param list<string> $placeholders
     */
    #[DataProvider('refusedRetirements')]
    public function testARetirementThatBreaksTheRingRulesIsRefused(array $indices, array $placeholders, string $reason): void
    {
        $ring = $this->ring(KeyMaterial::placeholder(), KeyMaterial::rawKey(), KeyMaterial::rawKey());
        $before = $ring->export();

        try {
            $ring->withRetired($indices, $placeholders, $this->slots, $this->rings);
            self::fail('The retirement was accepted.');
        } catch (KeyRingChangeRefused $refused) {
            self::assertStringContainsString($reason, $refused->getMessage());
        }
        self::assertSame($before, $ring->export());
    }

    public function testRestoringPutsTheKeptKeyBackIntoTheRetiredSlot(): void
    {
        $old = KeyMaterial::rawKey();
        $active = KeyMaterial::base64Key();
        $ring = $this->ring(KeyMaterial::placeholder(), $old, $active)
            ->withRetired([1], [KeyMaterial::placeholder()], $this->slots, $this->rings);

        $restored = $ring->withRestored(1, $old, $this->slots, $this->rings);

        self::assertSame([1], $restored->usableOldIndices());
        self::assertSame($old, $restored->slot(1)?->raw());
        self::assertSame(2, $restored->activeIndex());
    }

    public function testRestoringASlotThatIsNotRetiredIsRefused(): void
    {
        $ring = $this->ring(KeyMaterial::rawKey(), KeyMaterial::rawKey());

        $this->expectException(KeyRingChangeRefused::class);
        $this->expectExceptionMessage('Slot 0 is not retired');

        $ring->withRestored(0, KeyMaterial::rawKey(), $this->slots, $this->rings);
    }

    public function testRestoringTheActiveSlotIsRefused(): void
    {
        $ring = $this->ring(KeyMaterial::placeholder(), KeyMaterial::rawKey());

        $this->expectException(KeyRingChangeRefused::class);

        $ring->withRestored(1, KeyMaterial::rawKey(), $this->slots, $this->rings);
    }

    public function testRestoringASlotTheRingDoesNotHaveIsRefused(): void
    {
        $ring = $this->ring(KeyMaterial::placeholder(), KeyMaterial::rawKey());

        $this->expectException(KeyRingChangeRefused::class);

        $ring->withRestored(4, KeyMaterial::rawKey(), $this->slots, $this->rings);
    }

    public function testRestoringASlotWithAPlaceholderIsRefused(): void
    {
        $ring = $this->ring(KeyMaterial::placeholder(), KeyMaterial::rawKey());

        $this->expectException(KeyRingChangeRefused::class);

        $ring->withRestored(0, KeyMaterial::placeholder(), $this->slots, $this->rings);
    }

    public function testRestoringASlotWithAnEntryThatIsNotAKeyIsRefused(): void
    {
        $ring = $this->ring(KeyMaterial::placeholder(), KeyMaterial::rawKey());

        $this->expectException(InvalidKey::class);

        $ring->withRestored(0, 'not-a-key', $this->slots, $this->rings);
    }

    public function testRemovingTheAppendedKeyGivesBackThePreviousRing(): void
    {
        $ring = $this->ring(KeyMaterial::placeholder(), KeyMaterial::rawKey());
        $new = new Key(KeyMaterial::base64Key());
        $appended = $ring->appended($new, $this->slots, $this->rings);

        $removed = $appended->withoutSlot(2, $new, $this->rings);

        self::assertSame($ring->export(), $removed->export());
        self::assertSame($ring->fingerprint(), $removed->fingerprint());
    }

    public function testRemovingAgainAfterTheAppendedKeyIsGoneIsRefusedEvenWhenTheOldSlotZeroIsUsable(): void
    {
        $slotZero = KeyMaterial::rawKey();
        $oldActive = KeyMaterial::rawKey();
        $new = new Key(KeyMaterial::base64Key());
        $alreadyRemoved = $this->ring($slotZero, $oldActive);

        try {
            $alreadyRemoved->withoutSlot(2, $new, $this->rings);
            self::fail('A slot the ring no longer has was removed.');
        } catch (KeyRingChangeRefused $refused) {
            self::assertStringContainsString('Only the active slot, 1', $refused->getMessage());
        }

        try {
            $alreadyRemoved->withoutSlot(1, $new, $this->rings);
            self::fail('The previous active key was removed in place of the appended one.');
        } catch (KeyRingChangeRefused $refused) {
            self::assertStringContainsString('does not hold the key ' . $new->fingerprint(), $refused->getMessage());
        }

        self::assertSame($slotZero . "\n" . $oldActive, $alreadyRemoved->export());
    }

    public function testRemovingAnActiveSlotThatHoldsAnotherKeyIsRefused(): void
    {
        $ring = $this->ring(KeyMaterial::placeholder(), KeyMaterial::rawKey(), KeyMaterial::rawKey());

        $this->expectException(KeyRingChangeRefused::class);

        $ring->withoutSlot(2, new Key(KeyMaterial::rawKey()), $this->rings);
    }

    public function testRemovingTheActiveSlotByTheSameBytesInAnotherEncodingIsRefused(): void
    {
        $active = KeyMaterial::rawKey();
        $ring = $this->ring(KeyMaterial::rawKey(), $active);

        $this->expectException(KeyRingChangeRefused::class);

        $ring->withoutSlot(1, new Key('base64' . base64_encode($active)), $this->rings);
    }

    public function testRemovingTheOnlySlotIsRefused(): void
    {
        $only = KeyMaterial::rawKey();
        $ring = $this->ring($only);

        $this->expectException(KeyRingChangeRefused::class);
        $this->expectExceptionMessage('only slot');

        $ring->withoutSlot(0, new Key($only), $this->rings);
    }

    public function testRemovingASlotThatWouldLeaveARetiredSlotActiveIsRefused(): void
    {
        $active = KeyMaterial::rawKey();
        $ring = $this->ring(KeyMaterial::rawKey(), KeyMaterial::placeholder(), $active);

        $this->expectException(KeyRingChangeRefused::class);
        $this->expectExceptionMessage('retired slot 1');

        $ring->withoutSlot(2, new Key($active), $this->rings);
    }

    public function testDumpingARingShowsFingerprintsAndNeverAnEntry(): void
    {
        $entries = [KeyMaterial::placeholder(), KeyMaterial::rawKey(), KeyMaterial::base64Key()];
        $ring = $this->ring(...$entries);

        ob_start();
        var_dump($ring);
        $dumped = (string) ob_get_clean();
        $printed = print_r($ring, true);

        foreach ([$dumped, $printed] as $output) {
            self::assertStringContainsString($ring->fingerprint(), $output);
            self::assertStringContainsString($ring->active($this->keys)->fingerprint(), $output);
            foreach ($entries as $entry) {
                self::assertStringNotContainsString($entry, $output);
            }
        }
    }

    public function testARingIsNeverSerialised(): void
    {
        $this->expectException(\LogicException::class);

        serialize($this->ring(KeyMaterial::rawKey()));
    }

    private function ring(string ...$entries): KeyRing
    {
        $slots = [];
        foreach (array_values($entries) as $index => $entry) {
            $slots[] = new KeySlot($index, $entry);
        }

        return new KeyRing($slots, $this->keys);
    }
}
