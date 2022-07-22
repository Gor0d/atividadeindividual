# SPDX-License-Identifier: LGPL-2.1-or-later

# Copyright (c) 2019 Red Hat, Inc.
# Copyright (c) 2019 Tomáš Mráz <tmraz@fedoraproject.org>

from .configgenerator import ConfigGenerator


class KRB5Generator(ConfigGenerator):
	CONFIG_NAME = 'krb5'
	SCOPES = {'kerberos', 'krb5'}

	cipher_map = {
		'AES-256-CTR':'',
		'AES-128-CTR':'',
		'AES-256-GCM':'',
		'AES-256-CCM':'',
		'CHACHA20-POLY1305':'',
		'CAMELLIA-256-GCM':'',
		'AES-128-GCM':'',
		'AES-128-CCM':'',
		'CAMELLIA-128-GCM':'',

		'AES-256-CBC':'aes256-cts-hmac-sha1-96 aes256-cts-hmac-sha384-192',
		'AES-128-CBC':'aes128-cts-hmac-sha1-96 aes128-cts-hmac-sha256-128',
		'CAMELLIA-256-CBC':'camellia256-cts-cmac',
		'CAMELLIA-128-CBC':'camellia128-cts-cmac',
		'RC4-128':'arcfour-hmac-md5',
		'DES-CBC':'',
		'CAMELLIA-128-CTS':'camellia128-cts-cmac',
		'3DES-CBC':''
	}

	@classmethod
	def generate_config(cls, policy):
		p = policy.enabled
		sep = ' '

		cfg = '[libdefaults]\n'
		cfg += 'permitted_enctypes = '
		s = ''
		for i in p['cipher']:
			try:
				s = cls.append(s, cls.cipher_map[i], sep)
			except KeyError:
				pass
		if 'RC4-128' in p['cipher'] and 'MD5' in p['hash']:
			s = cls.append(s, 'arcfour-hmac-md5', sep)

		cfg += s + '\n'

		# By default libkrb5 sets the min_bits to 2048, don't
		# go lower than that.
		if policy.integers['min_dh_size'] > 2048:
			# $string .= "pkinit_dh_min_bits=$min_dh_size\n";
			# krb5.conf only accepts 2048 or 4096
			cfg += 'pkinit_dh_min_bits=4096\n'

		return cfg

	@classmethod
	def test_config(cls, config):  # pylint: disable=unused-argument
		return True
