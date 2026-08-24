<?php

declare(strict_types=1);

namespace Tests\ThreeBRS\EnterpriseSecurityBundle\Unit\Resources;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Yaml\Yaml;

/**
 * Guards the catalogues in src/Resources/translations against the message ids `src/` actually
 * emits: an id with no default translation renders as the raw `three_brs.…` string to the end user,
 * which is exactly what shipping the catalogues is meant to prevent. Adding a user-facing id
 * without a default fails here.
 */
class TranslationCataloguesTest extends TestCase
{
    protected const CATALOGUE_DIR = __DIR__ . '/../../../src/Resources/translations';

    /**
     * `three_brs.*` string literals in `src/` that are not message ids: service ids, container
     * parameters, a cache pool, prefixes matched with `str_starts_with()`, and one log message.
     */
    protected const NOT_MESSAGE_IDS = [
        // Logged, never rendered — see AbstractDueDeletionsProcessor.
        'three_brs.account_deletion.completion_hook_failed',
        // Prefixes, not ids: PasswordPolicyFilteringValidator matches message templates against
        // them and the passkey one is a parameter-name prefix.
        'three_brs.passkey.',
        'three_brs.password_policy.',
        // Container ids.
        'three_brs.rate_limiter.cache_pool',
        'three_brs.validator.cidr_list',
        'three_brs.validator.password_history',
        'three_brs.validator.password_policy',
    ];

    public function testEveryMessageIdEmittedBySourceHasAnEnglishDefault(): void
    {
        $translated = [];
        foreach ($this->catalogueFiles() as $file) {
            $translated = array_merge($translated, $this->flatten($this->parse($file)));
        }

        self::assertNotEmpty($translated, 'No translation catalogue was found.');

        foreach ($this->messageIdsInSource() as $id => $files) {
            self::assertArrayHasKey(
                $id,
                $translated,
                sprintf('"%s" (emitted in %s) has no English default.', $id, implode(', ', $files)),
            );
        }
    }

    public function testEveryTranslatedIdIsStillEmittedBySource(): void
    {
        $emitted = $this->messageIdsInSource();

        foreach ($this->catalogueFiles() as $file) {
            foreach (array_keys($this->flatten($this->parse($file))) as $id) {
                self::assertArrayHasKey(
                    $id,
                    $emitted,
                    sprintf('"%s" is translated in %s but nothing in src/ emits it.', $id, basename($file)),
                );
            }
        }
    }

    /**
     * @return array<string, list<string>> message id => the source files emitting it
     */
    protected function messageIdsInSource(): array
    {
        $ids = [];

        foreach ($this->sourceFiles() as $file) {
            $contents = file_get_contents($file);
            self::assertIsString($contents);

            preg_match_all("/'(three_brs\\.[a-zA-Z0-9_.]+)'/", $contents, $matches);

            foreach ($matches[1] as $id) {
                if (in_array($id, static::NOT_MESSAGE_IDS, true)) {
                    continue;
                }

                $ids[$id][] = basename($file);
            }
        }

        self::assertNotEmpty($ids, 'No message ids were found in src/ — the scan is broken.');

        return array_map(static fn (array $files): array => array_values(array_unique($files)), $ids);
    }

    /**
     * @return list<string>
     */
    protected function sourceFiles(): array
    {
        $files = [];
        $directory = new \RecursiveDirectoryIterator(__DIR__ . '/../../../src', \FilesystemIterator::SKIP_DOTS);

        /** @var \SplFileInfo $file */
        foreach (new \RecursiveIteratorIterator($directory) as $file) {
            if ($file->getExtension() === 'php') {
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }

    /**
     * @return list<string>
     */
    protected function catalogueFiles(): array
    {
        $files = glob(static::CATALOGUE_DIR . '/*.yaml');
        self::assertIsArray($files);
        self::assertNotEmpty($files);

        return $files;
    }

    /**
     * @return array<string, mixed>
     */
    protected function parse(string $file): array
    {
        $parsed = Yaml::parseFile($file);
        self::assertIsArray($parsed, sprintf('%s does not parse to a mapping.', basename($file)));

        /** @var array<string, mixed> $parsed */
        return $parsed;
    }

    /**
     * @param array<string, mixed> $tree
     *
     * @return array<string, string>
     */
    protected function flatten(array $tree, string $prefix = ''): array
    {
        $flat = [];

        foreach ($tree as $key => $value) {
            $path = $prefix === '' ? (string) $key : $prefix . '.' . $key;

            if (is_array($value)) {
                /** @var array<string, mixed> $value */
                $flat = array_merge($flat, $this->flatten($value, $path));

                continue;
            }

            self::assertIsString($value, sprintf('"%s" does not translate to a string.', $path));
            self::assertNotSame('', $value, sprintf('"%s" translates to an empty string.', $path));

            $flat[$path] = $value;
        }

        return $flat;
    }
}
