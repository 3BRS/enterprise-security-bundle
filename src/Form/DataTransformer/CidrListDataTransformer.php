<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Form\DataTransformer;

class CidrListDataTransformer implements CidrListDataTransformerInterface
{
    /**
     * Model side is `list<string>` (array of CIDRs), view side is a newline-separated
     * string for the textarea widget.
     */
    public function transform(mixed $value): string
    {
        if (! is_array($value)) {
            return '';
        }

        $lines = [];
        foreach ($value as $item) {
            if ($item === '') {
                continue;
            }
            $lines[] = $item;
        }

        return implode("\n", $lines);
    }

    /**
     * @return list<string>
     */
    public function reverseTransform(mixed $value): array
    {
        if (! is_string($value) || $value === '') {
            return [];
        }

        $lines = preg_split('/\r\n|\r|\n/', $value);
        if ($lines === false) {
            return [];
        }

        $items = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line !== '') {
                $items[] = $line;
            }
        }

        return $items;
    }
}
