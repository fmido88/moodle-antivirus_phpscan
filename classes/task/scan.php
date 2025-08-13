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

namespace antivirus_phpscan\task;

use antivirus_phpscan\scanner;
use antivirus_phpscan\scans;
use core_php_time_limit;
use MalwareScanner;
use RoundingMode;

defined('MOODLE_INTERNAL') || die();
require_once(__DIR__ . '/../../scr34m/php-malware-scanner/scan.php');

/**
 * Class scan
 *
 * @package    antivirus_phpscan
 * @copyright  2025 Mohammad Farouk <phun.for.physics@gmail.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class scan extends \core\task\scheduled_task {
    /**
     * Return the task name.
     * @return string
     */
    public function get_name() {
        return get_string('scansystem', 'antivirus_phpscan');
    }

    /**
     * Execute scanning the files.
     */
    public function execute() {
        core_php_time_limit::raise();
        raise_memory_limit(MEMORY_HUGE);
        $lastscan = (int)get_config('antivirus_phpscan', 'lastscan');
        $start = time();

        $files = self::get_files($lastscan);

        $scanner = scans::get_malware_scanner();
        $problems = [];
        foreach ($files as $file) {
            $infected = $scanner->scan($file);
            if ($infected) {
                $problems[] = $infected;
            }
        }

        mtrace("Infected files: " . count($problems));
        foreach($problems as $in) {
            // Todo: save files to log table.
            mtrace($in);
        }

        set_config('lastscan', $start, 'antivirus_phpscan');
    }

    public static function get_files($timemodified) {
        global $CFG;
        $dirs = array_merge(glob($CFG->dataroot . '/*'), glob($CFG->dirroot . '/*'));

        $timemodified = floor($timemodified / 100) * 100;
        foreach ($dirs as $dir) {
            self::check_dir_r($dir, $timemodified, $files);
        }

        return array_unique($files);
    }

    public static function get_white_list() {
        global $CFG;
        $relativepaths = [

        ];
    }
    protected static function check_dir_r($path, $timemodified, &$files = []) {
        if (is_file($path)) {
            if (filemtime($path) >= $timemodified) {
                $files[] = $path;
            }
            return;
        }

        $dir = dir($path);
        while (false !== ($entry = $dir->read())) {
            if ($entry == '.' || $entry == '..') {
                continue;
            }
            $fullpath = $path . DIRECTORY_SEPARATOR . $entry;
            self::check_dir_r($fullpath, $timemodified, $files);
        }
    }
}
