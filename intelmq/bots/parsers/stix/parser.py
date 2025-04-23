"""
SPDX-FileCopyrightText: 2025 Ladislav Baco
SPDX-License-Identifier: AGPL-3.0-or-later

Parse indicators objects in STIX format received from TAXII collector
"""

import json

from intelmq.lib.bot import ParserBot


class StixParserBot(ParserBot):
    """Parse STIX indicators"""
    parse = ParserBot.parse_json_stream
    recover_line = ParserBot.recover_line_json_stream

    def parse_line(self, line, report):
        """ Parse one STIX object of indicator type """
        object_type = line.get('type', '')
        if object_type == 'indicator':
            event = self.new_event(report)
            event.add('raw', json.dumps(line))
            event.add('comment', line.get('description', ''))
            event.add('extra.labels', line.get('labels', None))
            event.add('time.source', line.get('valid_from', '1970-01-01T00:00:00Z'))
            # classification will be determined by expert bot specific for given TAXII collection
            event.add('classification.type', 'undetermined')

            pattern = line.get('pattern', '')
            # stix, pcre, sigma, snort, suricata, yara
            pattern_type = line.get('pattern_type', '')

            if pattern_type == 'stix':
                indicator = self.parse_stix_pattern(pattern)
                if indicator:
                    event.add(indicator[0], indicator[1])
                    yield event
            else:
                self.logger.warning('Unexpected type of pattern expression: %r, pattern: %r', pattern_type, pattern)
        else:
            self.logger.warning('Unexpected type of STIX object: %r', object_type)

    @staticmethod
    def parse_stix_pattern(pattern):
        """
        STIX Patterning:
        https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_e8slinrhxcc9
        """
        if pattern.count('[') != 1:
            print('Unsupported Pattern Expression. Only single Observation Expression is supported. Pattern: {}'.format(pattern))
            return

        value = pattern.split("'")[1]
        if pattern.startswith('[url:value = '):
            return ('source.url', value)
        if pattern.startswith('[domain-name:value = '):
            return ('source.fqdn', value)
        if pattern.startswith('[ipv4-addr:value = '):
            # remove port, sometimes the port is present in ETI
            value = value.split(':')[0]
            # strip CIDR if IPv4 network contains single host only
            value = value[:-3] if value.endswith('/32') else value
            # check if pattern is in CIDR notation
            if value.rfind('/') > -1:
                return ('source.network', value)
            else:
                return ('source.ip', value)
        if pattern.startswith('[ipv6-addr:value = '):
            # strip CIDR if IPv6 network contains single host only
            value = value[:-4] if value.endswith('/128') else value
            # check if pattern is in CIDR notation
            if value.rfind('/') > -1:
                return ('source.network', value)
            else:
                return ('source.ip', value)


BOT = StixParserBot
