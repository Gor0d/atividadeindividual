# SPDX-License-Identifier: LGPL-2.1-or-later

# Copyright (c) 2019 Red Hat, Inc.
# Copyright (c) 2019 Tomáš Mráz <tmraz@fedoraproject.org>

from subprocess import call, CalledProcessError
from tempfile import mkstemp

import os

from .configgenerator import ConfigGenerator


class LibreswanGenerator(ConfigGenerator):
	CONFIG_NAME = 'libreswan'
	SCOPES = {'ipsec', 'ike', 'libreswan'}

	RELOAD_CMD = 'systemctl try-restart ipsec.service 2>/dev/null || :\n'

	group_map = {
		'X448':'',
		'X25519':'',
		# Disabled for now as it cannot be prioritized over others
		# 'X25519':'dh31',
		'SECP256R1':'dh19',
		'SECP384R1':'dh20',
		'SECP521R1':'dh21',
		'FFDHE-6144':'',
		'FFDHE-1536':'dh5',
		'FFDHE-2048':'dh14',
		'FFDHE-3072':'dh15',
		'FFDHE-4096':'dh16',
		'FFDHE-8192':'dh18'
	}

	cipher_map = {
		'AES-256-CBC':'aes256',
		'AES-192-CBC':'aes192',
		'AES-128-CBC':'aes128',
		'AES-256-GCM':'aes_gcm256',
		'AES-192-GCM':'aes_gcm192',
		'AES-128-GCM':'aes_gcm128',
		'CHACHA20-POLY1305':'chacha20_poly1305'
		# Unused for IKEv2
		# '3DES-CBC':'3des'
	}

	cipher_prf_map = {
		'AES-256-CBC-HMAC-SHA2-512':'sha2_512',
		'AES-256-CBC-HMAC-SHA2-256':'sha2_256',
		'AES-192-CBC-HMAC-SHA2-512':'sha2_512',
		'AES-192-CBC-HMAC-SHA2-256':'sha2_256',
		'AES-128-CBC-HMAC-SHA2-256':'sha2_256',
		# Not needed for IKEv2
		# 'AES-256-CBC-HMAC-SHA1':'sha1',
		# 'AES-128-CBC-HMAC-SHA1':'sha1',
		'AES-256-GCM-HMAC-SHA2-512':'sha2_512',
		'AES-256-GCM-HMAC-SHA2-256':'sha2_256',
		'AES-192-GCM-HMAC-SHA2-512':'sha2_512',
		'AES-192-GCM-HMAC-SHA2-256':'sha2_256',
		'AES-128-GCM-HMAC-SHA2-512':'sha2_512',
		'AES-128-GCM-HMAC-SHA2-256':'sha2_256',
		'CHACHA20-POLY1305-HMAC-SHA2-512':'sha2_512',
		'CHACHA20-POLY1305-HMAC-SHA2-256':'sha2_256'
		# '3DES-CBC-HMAC-SHA1':'sha1'
	}

	cipher_mac_map = {
		'AES-256-CBC-HMAC-SHA2-512':'sha2_512',
		'AES-192-CBC-HMAC-SHA2-512':'sha2_512',
		'AES-256-CBC-HMAC-SHA2-256':'sha2_256',
		'AES-192-CBC-HMAC-SHA2-256':'sha2_256',
		'AES-128-CBC-HMAC-SHA2-256':'sha2_256',
		'AES-256-CBC-HMAC-SHA1':'sha1',
		'AES-192-CBC-HMAC-SHA1':'sha1',
		'AES-128-CBC-HMAC-SHA1':'sha1',
		'AES-256-GCM-AEAD':'',
		'AES-192-GCM-AEAD':'',
		'AES-128-GCM-AEAD':'',
		'CHACHA20-POLY1305-AEAD':''
		# '3DES-CBC-HMAC-SHA1':'3des-sha1'
	}

	mac_ike_prio_map = {
		'AEAD':0,
		'HMAC-SHA2-512':1,
		'HMAC-SHA2-256':2,
		'HMAC-SHA1':3
	}

	mac_esp_prio_map = {
		'AEAD':0,
		'HMAC-SHA2-512':1,
		'HMAC-SHA1':2,
		'HMAC-SHA2-256':3
	}

	@classmethod
	def __get_ike_prio(cls, key):
		if key not in cls.mac_ike_prio_map:
			return 99
		return cls.mac_ike_prio_map[key]

	@classmethod
	def __get_esp_prio(cls, key):
		if key not in cls.mac_esp_prio_map:
			return 99
		return cls.mac_esp_prio_map[key]

	@classmethod
	def generate_config(cls, policy):
		cfg = 'conn %default\n'
		sep = ','
		p = policy.enabled

		s = ''
		proto = p['protocol']
		if 'IKEv2' in proto:
			s = 'ikev2=insist'
		elif 'IKEv1' in proto:  # and 'IKEv2' not in proto
			s = 'ikev2=never'
		if s:
			cfg += '\t' + s + '\n'

		cfg += '\tpfs=yes\n'

		sorted_macs = sorted(p['mac'],
			key=cls.__get_ike_prio)

		tmp = ''
		for cipher in p['cipher']:
			try:
				cm = cls.cipher_map[cipher]
			except KeyError:
				continue
			combo = cm + '-'
			s = ''
			for mac in sorted_macs:
				try:
					mm = cls.cipher_prf_map[cipher + '-' + mac]
				except KeyError:
					continue
				s = cls.append(s, mm, '+')
			if not s:
				continue
			combo += s
			s = ''
			for i in p['group']:
				try:
					group = cls.group_map[i]
				except KeyError:
					continue
				s = cls.append(s, group, '+')
			combo = cls.append(combo, s, '-')
			tmp = cls.append(tmp, combo, sep)

		if tmp:
			cfg += '\tike=' + tmp + '\n'

		sorted_macs = sorted(p['mac'], key=cls.__get_esp_prio)

		tmp = ''
		for cipher in p['cipher']:
			try:
				cm = cls.cipher_map[cipher]
			except KeyError:
				continue
			combo = cm + '-'
			s = ''
			for mac in sorted_macs:
				try:
					mm = cls.cipher_mac_map[cipher + '-' + mac]
				except KeyError:
					continue
				if not mm:
					# Special handling for AEAD
					combo = cm
					break
				s = cls.append(s, mm, '+')
			combo += s
			if combo[-1:] == '-':
				continue
			tmp = cls.append(tmp, combo, sep)

		if tmp:
			cfg += '\tesp=' + tmp + '\n'

		return cfg

	@classmethod
	def test_config(cls, config):
		if not os.access('/usr/sbin/ipsec', os.X_OK):
			return True

		fd, path = mkstemp()

		ret = 255
		try:
			with os.fdopen(fd, 'w') as f:
				f.write(config)
			try:
				ret = call('/usr/sbin/ipsec readwriteconf --config ' + path +
					' >/dev/null',
					shell=True)
			except CalledProcessError:
				cls.eprint("/usr/sbin/ipsec: Execution failed")
		finally:
			os.unlink(path)

		if ret:
			cls.eprint("There is an error in libreswan generated policy")
			cls.eprint("Policy:\n%s" % config)
			return False
		return True
