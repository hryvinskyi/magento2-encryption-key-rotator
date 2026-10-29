<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Cli;

use Hryvinskyi\EncryptionKeyRotator\Cli\Confirmation\Confirmation;
use Hryvinskyi\EncryptionKeyRotator\Cli\Option\CommandOptions;
use Hryvinskyi\EncryptionKeyRotator\Cli\OptionRefused;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectMagentoRootFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectProbeSettingsFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectQuestionFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectScanScopeFactory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\QuestionHelper;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * A writing command goes on only when confirmed up front or when the operator typed the expected word;
 * an input that ends first, or no way to ask at all, is never a confirmation.
 */
final class ConfirmationTest extends TestCase
{
    private Confirmation $confirmation;

    private Command $command;

    protected function setUp(): void
    {
        $options = new CommandOptions(new DirectMagentoRootFactory(), new DirectProbeSettingsFactory(), new DirectScanScopeFactory());
        $this->confirmation = new Confirmation(new QuestionHelper(), new DirectQuestionFactory(), $options);
        $this->command = new Command('writes');
        $options->addConfirmationOption($this->command);
    }

    public function testYesConfirmsUpFrontWithoutAsking(): void
    {
        self::assertFalse($this->confirmation->mustAsk($this->input(['--yes' => true], '', false)));
    }

    public function testWithoutInteractionAndWithoutYesTheCommandIsRefused(): void
    {
        $this->expectException(OptionRefused::class);
        $this->expectExceptionMessage('--yes');

        $this->confirmation->mustAsk($this->input([], '', false));
    }

    public function testOnlyTheExpectedWordConfirms(): void
    {
        $output = new BufferedOutput();

        self::assertTrue($this->confirmation->ask($this->input([], "0123abcd\n"), $output, '0123abcd'));
        self::assertFalse($this->confirmation->ask($this->input([], "yes\n"), $output, '0123abcd'));
        self::assertFalse($this->confirmation->ask($this->input([], "yes\n"), $output, Confirmation::START_WORD));
        self::assertStringContainsString('Type the run id 0123abcd to continue', $output->fetch());
    }

    public function testAnInputThatEndsBeforeTheAnswerIsNoConfirmation(): void
    {
        self::assertFalse($this->confirmation->ask($this->input([], ''), new BufferedOutput(), Confirmation::START_WORD));
    }

    /**
     * @param array<string, mixed> $parameters
     */
    private function input(array $parameters, string $typed, bool $interactive = true): ArrayInput
    {
        $input = new ArrayInput($parameters, $this->command->getDefinition());
        $input->setInteractive($interactive);
        $stream = fopen('php://memory', 'r+');
        self::assertIsResource($stream);
        fwrite($stream, $typed);
        rewind($stream);
        $input->setStream($stream);

        return $input;
    }
}
