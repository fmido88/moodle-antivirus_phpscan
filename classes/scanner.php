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

use MalwareScanner;

defined('MOODLE_INTERNAL') || die();
require_once(__DIR__ . '/../scr34m/php-malware-scanner/scan.php');

/**
 * Class scannar
 *
 * @package    antivirus_phpscan
 * @copyright  2025 Mohammad Farouk <phun.for.physics@gmail.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class scanner extends \core\antivirus\scanner {

    /**
     * Are the antivirus settings configured?
     * We use internal php code and no need for configurations.
     * @return true
     */
    public function is_configured() {
        return true;
    }

    /**
     * Scan file.
     *
     * @param string $file Full path to the file.
     * @param string $filename Name of the file (could be different from physical file if temp file is used).
     * @return int Scanning result constants.
     */
    public function scan_file($file, $filename) {
        
        $results = scans::scan_files([$filename => $file]);

        return !empty($results) ? self::SCAN_RESULT_FOUND : self::SCAN_RESULT_OK ;
    }
}
