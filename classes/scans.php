<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

namespace antivirus_phpscan;
use core\antivirus\quarantine;
use MalwareScanner;
use phpMussel\Core\Loader;

defined('MOODLE_INTERNAL') || die();
require_once(__DIR__ . '/../scr34m/php-malware-scanner/scan.php');
require_once(__DIR__ . '/../phpmussel/autoload.php');

/**
 * Helper class to initialize scanners.
 *
 * @package    antivirus_phpscan
 * @copyright  2025 Mohammad Farouk <phun.for.physics@gmail.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class scans {
    /**
     * Extensions to be scanned by malware scanner.
     */
    public static array $extensions = [
        'php',
        'html',
        'mustache',
        '.',
    ];
    /**
     * Initialize and return instance of php malware scanner.
     * @return MalwareScanner
     */
    public static function get_malware_scanner(): MalwareScanner {
        static $scan;
        if (!isset($scan) || !$scan instanceof MalwareScanner) {
            $scan = new MalwareScanner(false);
            $scan->setFlagNoStop(true);
            $scan->setFlagHideOk(true);
            $scan->setFlagScanEverything(true);
            $scan->setFlagHideWhitelist(true);
            $scan->setFlagLineNumber(true);
            $scan->setFlagPattern(true);
            $scan->setFlagComments(true);

            $scan->setFlagBase64(true);
            $scan->initializePatterns();

            $scan->setFlagBase64(false);
            $scan->setFlagExtraCheck(true);
            $scan->initializePatterns();

            $scan->setExtensions(self::$extensions);
        }
        return $scan;
    }

    /**
     * Initialize and return instance of php mussel scanner.
     * @return \phpMussel\Core\Scanner|\phpMussel\Core\Loader
     */
    public static function get_phpmussel_scanner($loaderonly = false) {
        static $scanner;
        static $loader;
        if (!isset($scan) || !$scan instanceof \phpMussel\Core\Scanner) {
            global $CFG;
            $cachedir = make_cache_directory('phpmussel');
            $quarntine = $CFG->dataroot . DIRECTORY_SEPARATOR . quarantine::DEFAULT_QUARANTINE_FOLDER;
            $vendordir = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'phpmussel';
            $loader = new \phpMussel\Core\Loader(
                $vendordir . DIRECTORY_SEPARATOR . 'config.yml',
                $cachedir,
                $quarntine,
                $vendordir . DIRECTORY_SEPARATOR . 'signatures',
                $vendordir);
            $scanner = new \phpMussel\Core\Scanner($loader);
        }

        if ($loaderonly) {
            return $loader;
        }

        return $scanner;
    }

    /**
     * Scan files both by malware scanner and php mussel scanner.
     * @param array $files
     * @return array
     */
    public static function scan_files(array $files) {
        $scanner = self::get_malware_scanner();
        $problems = [];
        ob_start();
        foreach($files as $file) {
            $infected = $scanner->scan($file);
            if ($infected) {
                $problems[] = $file;
            }
        }
        ob_end_clean();

        $scanner = self::get_phpmussel_scanner();
        $results = $scanner->scan($files, 3);

        /**
         * @var Loader
         */
        $loader = self::get_phpmussel_scanner(true);
        $integers = $loader->ScanResultsIntegers;
        foreach ($results as $file => $result) {
            if ($integers[$file] !== 1) {
                $problems[] = $file . ': ' . $result;
            }
        }

        return $problems;
    }

}
