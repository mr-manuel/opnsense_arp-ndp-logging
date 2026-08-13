/*
 * Copyright (C) 2026 github.com/mr-manuel
 * All rights reserved.
 *
 * License: BSD 2-Clause
 */

const ARPNDPLOGGING_EVENT_LABELS = {
    mac_change: 'MAC',
    ipv4_change: 'IPv4',
    ipv6_change: 'IPv6',
    hostname_change: 'Hostname',
    interface_change: 'Interface',
};

const ARPNDPLOGGING_FIELD_LABELS = {
    mac: 'MAC',
    vendor: 'Vendor',
    hostname: 'Hostname',
    ipv4: 'IPv4',
    ipv6: 'IPv6',
    interface: 'Interface',
};

const ARPNDPLOGGING_DEFAULT_COLUMNS = ['hostname', 'ipv4', 'mac'];

function arpndplogging_humanize_event_type(eventType) {
    if (eventType === 'new_entry') {
        return 'New device';
    }
    if (eventType === 'test') {
        return 'Test';
    }
    return eventType.split(',').map(function (tag) {
        return ARPNDPLOGGING_EVENT_LABELS[tag] || tag;
    }).join(', ');
}

export default class ArpNdpLogging extends BaseWidget {
    constructor(config) {
        super(config);
        this.tickTimeout = 15;
        this.configurable = true;
    }

    async getWidgetOptions() {
        return {
            columns: {
                id: 'columns',
                title: this.translations.columns,
                type: 'select_multiple',
                options: [
                    { value: 'hostname', label: this.translations.hostname },
                    { value: 'ipv4', label: this.translations.ip },
                    { value: 'ipv6', label: this.translations.ipv6 },
                    { value: 'mac', label: this.translations.mac },
                ],
                default: ARPNDPLOGGING_DEFAULT_COLUMNS,
            },
            limit: {
                id: 'limit',
                title: this.translations.limit,
                type: 'select',
                options: [
                    { value: '5', label: '5' },
                    { value: '7', label: '7' },
                    { value: '10', label: '10' },
                    { value: '20', label: '20' },
                    { value: '50', label: '50' },
                ],
                default: '7',
            },
        };
    }

    getMarkup() {
        let $container = $('<div></div>');

        let $error = $(
            '<div class="alert alert-danger" id="arpndplogging-error" style="display:none;"></div>'
        );

        let $total = $(
            '<table class="table table-condensed">' +
                '<tbody><tr><td>' + this.translations.total + '</td>' +
                '<td id="arpndplogging-total">-</td></tr></tbody>' +
            '</table>'
        );

        let $recent = $(
            '<table class="table table-condensed table-striped" id="arpndplogging-recent">' +
                '<thead><tr></tr></thead>' +
                '<tbody></tbody>' +
            '</table>'
        );

        $container.append($error);
        $container.append($total);
        $container.append($recent);

        return $container;
    }

    async onWidgetTick() {
        const config = await this.getWidgetConfig() || {};
        const columns = Array.isArray(config.columns) && config.columns.length > 0
            ? config.columns
            : ARPNDPLOGGING_DEFAULT_COLUMNS;
        const limit = parseInt(config.limit ?? '7', 10) || 7;

        const columnLabels = {
            hostname: this.translations.hostname,
            ipv4: this.translations.ip,
            ipv6: this.translations.ipv6,
            mac: this.translations.mac,
        };

        let data;
        try {
            data = await this.ajaxCall(
                '/api/arpndplogging/service/stats',
                JSON.stringify({ limit: limit }),
                'POST'
            );
        } catch (error) {
            return;
        }
        if (data === undefined) {
            return;
        }

        if (!data.running) {
            $('#arpndplogging-error').text(this.translations.not_running).show();
            return;
        }
        $('#arpndplogging-error').hide();

        $('#arpndplogging-total').text(data.total !== undefined ? data.total : '-');

        let $thead = $('#arpndplogging-recent thead tr');
        $thead.empty();
        columns.forEach(function (col) {
            $thead.append($('<th></th>').text(columnLabels[col] || col));
        });
        $thead.append($('<th></th>').text(this.translations.event));
        $thead.append($('<th></th>').text(this.translations.time));

        let $tbody = $('#arpndplogging-recent tbody');
        $tbody.empty();

        (data.recent || []).forEach(function (entry) {
            let $row = $('<tr></tr>');

            columns.forEach(function (col) {
                $row.append($('<td></td>').text(entry[col]));
            });

            let $eventCell = $('<td></td>');
            $eventCell.append($('<div></div>').text(arpndplogging_humanize_event_type(entry.event_type)));

            let changes = entry.changes || {};
            Object.keys(changes).forEach(function (key) {
                let label = ARPNDPLOGGING_FIELD_LABELS[key] || key;
                let $line = $('<div style="font-size:11px; white-space:nowrap;"></div>');
                $line.append($('<span></span>').text(label + ': '));
                $line.append($('<s style="color:#c0392b;"></s>').text(changes[key]));
                $line.append(document.createTextNode(' -> '));
                $line.append($('<span style="color:#1e8449; font-weight:600;"></span>').text(entry[key]));
                $eventCell.append($line);
            });
            $row.append($eventCell);

            $row.append($('<td></td>').text(entry.timestamp));

            $tbody.append($row);
        });
    }

    async onWidgetOptionsChanged(options) {
        await this.onWidgetTick();
    }
}
