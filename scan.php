<?php

use antivirus_phpscan\scans;
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

/**
 * TODO describe file scan
 *
 * @package    antivirus_phpscan
 * @copyright  2025 Mohammad Farouk <phun.for.physics@gmail.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require('../../../config.php');

require_admin();

$url = new moodle_url('/lib/antivirus/phpscan/scan.php', []);
$PAGE->set_url($url);
$PAGE->set_context(context_system::instance());

$PAGE->set_heading($SITE->fullname);

// $scanner = scans::get_phpmussel_scanner();

// $scan = new MalwareScanner(false);
// $scan->setFlagNoStop(true);
// $scan->setFlagHideOk(true);
// $scan->setFlagScanEverything(true);
// $scan->setFlagNoStop(true);
// $scan->setFlagHideWhitelist(true);
// $scan->setFlagBase64(true);

core_php_time_limit::raise();
raise_memory_limit(MEMORY_UNLIMITED);

echo $OUTPUT->header();

// $results = $scan->scan($CFG->dirroot. '/enrol');

echo '<pre>';
var_dump($results);
echo '</pre>';

echo $OUTPUT->footer();
