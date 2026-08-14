<?php

/*
 * Copyright (C) 2025 github.com/mr-manuel
 * All rights reserved.
 *
 * License: BSD 2-Clause
 */

namespace OPNsense\ArpNdpLogging\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;
use OPNsense\ArpNdpLogging\General;

class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\ArpNdpLogging\General';
    protected static $internalServiceTemplate = 'OPNsense/ArpNdpLogging';
    protected static $internalServiceEnabled = 'enabled';
    protected static $internalServiceName = 'arpndplogging';

    /**
     * remove database folder
     * @return array
     */
    public function resetdbAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("arpndplogging resetdb");
        return array("response" => $response);
    }

    /**
     * send a test mail using the currently saved configuration
     * @return array
     */
    public function testmailAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("arpndplogging testmail");
        return array("response" => $response);
    }

    /**
     * send a test webhook request using the currently saved configuration
     * @return array
     */
    public function testwebhookAction()
    {
        $backend = new Backend();
        $response = $backend->configdRun("arpndplogging testwebhook");
        return array("response" => $response);
    }

    /**
     * device count, recent activity and running state for the dashboard widget
     * @return array
     */
    public function statsAction()
    {
        $backend = new Backend();
        $status = trim((string)$backend->configdRun("arpndplogging status"));
        $running = strpos($status, "is running") !== false;

        $payload = json_decode((string)$this->request->getRawBody(), true);
        $limit = isset($payload['limit']) ? intval($payload['limit']) : 7;
        if ($limit < 1) {
            $limit = 1;
        } elseif ($limit > 100) {
            $limit = 100;
        }

        $dbFile = "/var/db/arpndplogging/arpndplogging.db";
        $total = 0;
        $recent = array();

        if (file_exists($dbFile)) {
            try {
                $db = new \SQLite3($dbFile, SQLITE3_OPEN_READONLY);
                $db->enableExceptions(true);

                $result = $db->query("SELECT COUNT(*) AS cnt FROM devices");
                $row = $result->fetchArray(SQLITE3_ASSOC);
                $total = intval($row['cnt']);

                $stmt = $db->prepare(
                    "SELECT mac, ipv4, ipv6, hostname, interface, vendor, event_type, message, changes, timestamp " .
                    "FROM events ORDER BY timestamp DESC LIMIT :limit"
                );
                $stmt->bindValue(':limit', $limit, SQLITE3_INTEGER);
                $result = $stmt->execute();
                while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                    $decoded = json_decode((string)$row['changes'], true);
                    $row['changes'] = is_array($decoded) ? $decoded : array();
                    $recent[] = $row;
                }

                $db->close();
            } catch (\Exception $e) {
                // database or events table not initialized yet, return defaults
            }
        }

        return array("running" => $running, "total" => $total, "recent" => $recent);
    }

}
