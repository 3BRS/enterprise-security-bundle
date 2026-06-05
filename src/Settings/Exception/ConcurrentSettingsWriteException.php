<?php

declare(strict_types=1);

namespace ThreeBRS\EnterpriseSecurityBundle\Settings\Exception;

/**
 * Thrown by SettingsWriter::flush() when a concurrent writer committed the same
 * (path, scope) row between our find() and our flush(). The caller should treat
 * this as "settings were not saved" — typically by surfacing a flash message and
 * inviting the admin to reload and retry.
 */
class ConcurrentSettingsWriteException extends \RuntimeException
{
}
