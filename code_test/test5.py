# _*_ coding:utf-8 _*_
# Copyright 2012 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import base64
import re

import rsa

code_str_1 = ('1831844656443940519921183779932675539236799754669240155436582'
              '9079874975463381196051247297236307178297203036283103580594504'
              '7455911655791775965457576449823200597336065479143639479139641'
              '8945617403924697950459119180499174776693201450350271445815017'
              '2982524075102708376479216149242166042059157401878686405153613'
              '8806084914274299232685182203566764824574238148660658283191079'
              '7784229253003680548170610487463222591401236589165272781767870'
              '7823164558720309668969722773605822117403476985891810390319930'
              '2322950591322599138538123818652486572419266326092746579461329'
              '8843062800432391231500216120710276610137128166984358661645307'
              '3492069')

code_str_2 = ('1540116889239072930522563228013037249369786021366176855281073'
              '5650107742924337456740829242683072547174510388012863074152878'
              '7018336698874328328985343582789238947666466391516464520814109'
              '1046332895253839160631360404740902546588879562907974986105672'
              '4160963677589136389276360068712991881188635010555737355246535'
              '6942296266969681907118107030571921691655018143754282217205115'
              '4764105620942760989795445963172661279443376569071198461343597'
              '9607952928934979895485713490879257583477778799888709544247552'
              '8163225533514801720247881012090613274058247401555615190111549'
              '0774134852818321229167679831696369735696848610095878341839165'
              '3705473')

code_str_3 = ('2844360469567548367128871738878120824229782877887958572986584'
              '5901233387165792225914315728712142762717767575278285154965794'
              '0617042333650957307959658196511569296148251044837328867402692'
              '0199208205904158112715533726974307247212940478107186040195171'
              '2864772598522573438871210150366533978627038818848281861956182'
              '83960620917485940544081')

code_str_4 = ('6440269002622058675117594954479314013958558448964474896652217'
              '6054150269559700438136711049662668178861851939095390092680146'
              '4307528532715453011813813713290308452222986389602241889092622'
              '6704745793881107438612038313999338266584858484149150359026765'
              '186339757868338340025026562896935062708104149')


class ParseError(Exception):
    def __init__(self, message, lineno, line):
        self.msg = message
        self.line = line
        self.lineno = lineno

    def __str__(self):
        return 'at line %d, %s: %r' % (self.lineno, self.msg, self.line)


class BaseParser(object):
    lineno = 0
    parse_exc = ParseError

    def _assignment(self, key, value):
        self.assignment(key, value)
        return None, []

    def _get_section(self, line):
        if not line.endswith(']'):
            return self.error_no_section_end_bracket(line)
        if len(line) <= 2:
            return self.error_no_section_name(line)

        return line[1:-1]

    def _split_key_value(self, line):
        colon = line.find(':')
        equal = line.find('=')
        if colon < 0 and equal < 0:
            return self.error_invalid_assignment(line)

        if colon < 0 or (equal >= 0 and equal < colon):
            key, value = line[:equal], line[equal + 1:]
        else:
            key, value = line[:colon], line[colon + 1:]

        value = value.strip()
        if value and value[0] == value[-1] and value.startswith(("\"", "'")):
            value = value[1:-1]
        return key.strip(), [value]

    def parse(self, lineiter):
        key = None
        value = []

        for line in lineiter:
            self.lineno += 1

            line = line.rstrip()
            if not line:
                # Blank line, ends multi-line values
                if key:
                    key, value = self._assignment(key, value)
                continue
            elif line.startswith((' ', '\t')):
                # Continuation of previous assignment
                if key is None:
                    self.error_unexpected_continuation(line)
                else:
                    value.append(line.lstrip())
                continue

            if key:
                # Flush previous assignment, if any
                key, value = self._assignment(key, value)

            if line.startswith('['):
                # Section start
                section = self._get_section(line)
                if section:
                    self.new_section(section)
            elif line.startswith(('#', ';')):
                self.comment(line[1:].lstrip())
            else:
                key, value = self._split_key_value(line)
                if value[0].find('!###') >= 0 and value[0].find('!%%%') >= 0:
                    value = self.convert_password(value)
                if not key:
                    return self.error_empty_key(line)

        if key:
            # Flush previous assignment, if any
            self._assignment(key, value)

    def convert_password(self, value):
        code_long_1 = long(code_str_1)
        code_long_2 = long(code_str_2)
        code_long_3 = long(code_str_3)
        code_long_4 = long(code_str_4)
        privateKey = rsa.key.PrivateKey(code_long_1, 65537, code_long_2,
                                        code_long_3, code_long_4)
        value_str = value[0]
        password_encode = re.findall(r"!###(.+?)!%%%", value_str)[0]
        if len(password_encode) != 344:
            raise ValueError()
        password_encrypt = base64.urlsafe_b64decode(password_encode)
        password_decrypt = rsa.decrypt(password_encrypt, privateKey)
        old_pass = '!###'+password_encode+'!%%%'
        value_str = value_str.replace(old_pass, password_decrypt)
        value = [value_str]
        return value

    def assignment(self, key, value):
        """Called when a full assignment is parsed."""
        raise NotImplementedError()

    def new_section(self, section):
        """Called when a new section is started."""
        raise NotImplementedError()

    def comment(self, comment):
        """Called when a comment is parsed."""
        pass

    def error_invalid_assignment(self, line):
        raise self.parse_exc("No ':' or '=' found in assignment",
                             self.lineno, line)

    def error_empty_key(self, line):
        raise self.parse_exc('Key cannot be empty', self.lineno, line)

    def error_unexpected_continuation(self, line):
        raise self.parse_exc('Unexpected continuation line',
                             self.lineno, line)

    def error_no_section_end_bracket(self, line):
        raise self.parse_exc('Invalid section (must end with ])',
                             self.lineno, line)

    def error_no_section_name(self, line):
        raise self.parse_exc('Empty section name', self.lineno, line)
