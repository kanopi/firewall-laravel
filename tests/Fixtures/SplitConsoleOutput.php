<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Fixtures;

use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\ConsoleSectionOutput;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Output\StreamOutput;

/**
 * A console output with stdout and stderr kept apart, as a real terminal has.
 *
 * Artisan's test output is a single buffer, so it cannot tell whether a
 * command wrote something to the wrong stream — which is the whole question
 * for `--json`, where anything extra on stdout breaks the parser (#8).
 */
final class SplitConsoleOutput extends StreamOutput implements ConsoleOutputInterface
{
    private OutputInterface $stderr;

    public function __construct()
    {
        parent::__construct(self::memory(), decorated: false);
        $this->stderr = new StreamOutput(self::memory(), decorated: false);
    }

    public function stdout(): string
    {
        return self::read($this->getStream());
    }

    public function stderr(): string
    {
        return $this->stderr instanceof StreamOutput ? self::read($this->stderr->getStream()) : '';
    }

    public function getErrorOutput(): OutputInterface
    {
        return $this->stderr;
    }

    public function setErrorOutput(OutputInterface $error): void
    {
        $this->stderr = $error;
    }

    public function section(): ConsoleSectionOutput
    {
        throw new \LogicException('Sections are not used by the firewall commands.');
    }

    /**
     * @return resource
     */
    private static function memory()
    {
        $stream = fopen('php://memory', 'w+');

        if ($stream === false) {
            throw new \RuntimeException('Unable to open a memory stream.');
        }

        return $stream;
    }

    /**
     * @param resource $stream
     */
    private static function read($stream): string
    {
        rewind($stream);

        return (string) stream_get_contents($stream);
    }
}
