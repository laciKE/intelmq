# SPDX-FileCopyrightText: 2025 Ladislav Baco
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# -*- coding: utf-8 -*-
"""
Test with example reports (STIX objects usually collected from TAXII server)
"""
import unittest

import re
import requests_mock

import intelmq.lib.bot as bot
import intelmq.lib.test as test
from intelmq.bots.parsers.stix.parser import StixParserBot


EXAMPLE_REPORT = {'__type': 'Report',
                  'feed.name': 'Taxii Feed',
                  'feed.code': 'feed stix2.1',
                  'feed.provider': 'Taxii Provider',
                  'feed.documentation': 'Taxii Documentation',
                  'feed.accuracy': 100.0,
                  'feed.url': 'http://localhost/feed',
                  'raw': 'eyJpZCI6ICJpbmRpY2F0b3ItLTAiLCAidHlwZSI6ICJpbmRpY2F0b3IiLCAic3BlY192ZXJzaW9uIjogIjIuMSIsICJjcmVhdGVkIjogIjE5NzAtMDEtMDFUMDA6MDA6MDAuMDAwWiIsICJtb2RpZmllZCI6ICIxOTcwLTAxLTAxVDAwOjAwOjAwLjAwMFoiLCAicGF0dGVybiI6ICJbdXJsOnZhbHVlID0gJ2h0dHA6Ly9leGFtcGxlLm9yZyddIiwgInBhdHRlcm5fdHlwZSI6ICJzdGl4IiwgInZhbGlkX2Zyb20iOiAiMTk3MC0wMS0wMVQwMDowMDowMFoifQ=='
                  }

EXAMPLE_EVENT = {'__type': 'Event',
                 'feed.name': 'Taxii Feed',
                 'feed.code': 'feed stix2.1',
                 'feed.provider': 'Taxii Provider',
                 'feed.documentation': 'Taxii Documentation',
                 'feed.accuracy': 100.0,
                 'feed.url': 'http://localhost/feed',
                 'source.url': 'http://example.org',
                 'time.source': '1970-01-01T00:00:00+00:00',
                 'classification.type': 'undetermined',
                 'raw': 'eyJpZCI6ICJpbmRpY2F0b3ItLTAiLCAidHlwZSI6ICJpbmRpY2F0b3IiLCAic3BlY192ZXJzaW9uIjogIjIuMSIsICJjcmVhdGVkIjogIjE5NzAtMDEtMDFUMDA6MDA6MDAuMDAwWiIsICJtb2RpZmllZCI6ICIxOTcwLTAxLTAxVDAwOjAwOjAwLjAwMFoiLCAicGF0dGVybiI6ICJbdXJsOnZhbHVlID0gJ2h0dHA6Ly9leGFtcGxlLm9yZyddIiwgInBhdHRlcm5fdHlwZSI6ICJzdGl4IiwgInZhbGlkX2Zyb20iOiAiMTk3MC0wMS0wMVQwMDowMDowMFoifQ=='
                 }


class TestStixParserBot(test.BotTestCase, unittest.TestCase):
    """
    A TestCase for a StixParserBot.
    """

    @classmethod
    def set_bot(cls):
        cls.bot_reference = StixParserBot
        cls.sysconfig = {}

    def test_event(self):
        """ Test if correct Event has been produced. """
        self.input_message = EXAMPLE_REPORT
        self.run_bot()
        self.assertMessageEqual(0, EXAMPLE_EVENT)

    def test_pattern_url(self):
        """ Test if url pattern is parsed. """
        indicator = self.bot_reference.parse_stix_pattern("[url:value = 'http://example.org']")
        self.assertEqual(str(indicator[0]), 'source.url')
        self.assertEqual(str(indicator[1]), 'http://example.org')

    def test_pattern_url(self):
        """ Test if domain pattern is parsed. """
        indicator = self.bot_reference.parse_stix_pattern("[domain-name:value = 'example.org']")
        self.assertEqual(str(indicator[0]), 'source.fqdn')
        self.assertEqual(str(indicator[1]), 'example.org')

    def test_pattern_ipv4(self):
        """ Test if ipv4 pattern is parsed. """
        indicator = self.bot_reference.parse_stix_pattern("[ipv4-addr:value = '127.0.0.1']")
        self.assertEqual(str(indicator[0]), 'source.ip')
        self.assertEqual(str(indicator[1]), '127.0.0.1')

    def test_pattern_ipv4_cidr(self):
        """ Test if ipv4 cidr pattern is parsed. """
        indicator = self.bot_reference.parse_stix_pattern("[ipv4-addr:value = '127.0.0.0/8']")
        self.assertEqual(str(indicator[0]), 'source.network')
        self.assertEqual(str(indicator[1]), '127.0.0.0/8')

    def test_pattern_ipv4_cidr_single_host(self):
        """ Test if ipv4 cidr with single host pattern is parsed. """
        indicator = self.bot_reference.parse_stix_pattern("[ipv4-addr:value = '127.0.0.1/32']")
        self.assertEqual(str(indicator[0]), 'source.ip')
        self.assertEqual(str(indicator[1]), '127.0.0.1')

    def test_pattern_ipv6(self):
        """ Test if ipv6 pattern is parsed. """
        indicator = self.bot_reference.parse_stix_pattern("[ipv6-addr:value = '::1']")
        self.assertEqual(str(indicator[0]), 'source.ip')
        self.assertEqual(str(indicator[1]), '::1')

    def test_pattern_ipv6_cidr(self):
        """ Test if ipv6 cidr pattern is parsed. """
        indicator = self.bot_reference.parse_stix_pattern("[ipv6-addr:value = 'fe:80::/10']")
        self.assertEqual(str(indicator[0]), 'source.network')
        self.assertEqual(str(indicator[1]), 'fe:80::/10')

    def test_pattern_ipv6_cidr_single_host(self):
        """ Test if ipv6 cidr with single host pattern is parsed. """
        indicator = self.bot_reference.parse_stix_pattern("[ipv6-addr:value = 'fe:80::1/128']")
        self.assertEqual(str(indicator[0]), 'source.ip')
        self.assertEqual(str(indicator[1]), 'fe:80::1')


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
