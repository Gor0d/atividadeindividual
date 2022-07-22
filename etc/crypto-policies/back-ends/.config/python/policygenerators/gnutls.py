# SPDX-License-Identifier: LGPL-2.1-or-later

# Copyright (c) 2019 Red Hat, Inc.
# Copyright (c) 2019 Tomáš Mráz <tmraz@fedoraproject.org>

from subprocess import call, CalledProcessError
from tempfile import mkstemp

import os

from .configgenerator import ConfigGenerator


class GnuTLSGenerator(ConfigGenerator):
	CONFIG_NAME = 'gnutls'
	SCOPES = {'tls', 'ssl', 'gnutls'}

	mac_not_map = {
		'AEAD':'-AEAD',
		'HMAC-SHA1':'-SHA1',
		'HMAC-MD5':'-MD5',
		'HMAC-SHA2-256':'-SHA256',
		'HMAC-SHA2-384':'-SHA384',
		'HMAC-SHA2-512':'-SHA512'
	}

	group_not_map = {
		'X448':'-GROUP-X448',
		'X25519':'-GROUP-X25519',
		'SECP256R1':'-GROUP-SECP256R1',
		'SECP384R1':'-GROUP-SECP384R1',
		'SECP521R1':'-GROUP-SECP521R1',
		'FFDHE-6144':'',
		'FFDHE-2048':'-GROUP-FFDHE2048',
		'FFDHE-3072':'-GROUP-FFDHE3072',
		'FFDHE-4096':'-GROUP-FFDHE4096',
		'FFDHE-8192':'-GROUP-FFDHE8192'
	}

	sign_not_map = {
		'RSA-MD5':'-SIGN-RSA-MD5',
		'RSA-SHA1':'-SIGN-RSA-SHA1',
		'DSA-SHA1':'-SIGN-DSA-SHA1',
		'ECDSA-SHA1':'-SIGN-ECDSA-SHA1',
		'RSA-SHA2-224':'-SIGN-RSA-SHA224',
		'DSA-SHA2-224':'-SIGN-DSA-SHA224',
		'ECDSA-SHA2-224':'-SIGN-ECDSA-SHA224',
		'RSA-SHA2-256':'-SIGN-RSA-SHA256',
		'DSA-SHA2-256':'-SIGN-DSA-SHA256',
		'ECDSA-SHA2-256':'-SIGN-ECDSA-SHA256',
		'RSA-SHA2-384':'-SIGN-RSA-SHA384',
		'DSA-SHA2-384':'-SIGN-DSA-SHA384',
		'ECDSA-SHA2-384':'-SIGN-ECDSA-SHA384',
		'RSA-SHA2-512':'-SIGN-RSA-SHA512',
		'DSA-SHA2-512':'-SIGN-DSA-SHA512',
		'ECDSA-SHA2-512':'-SIGN-ECDSA-SHA512',
		# These are only available under 3.6.3+
		'RSA-PSS-SHA2-256':'-SIGN-RSA-PSS-SHA256:-SIGN-RSA-PSS-RSAE-SHA256',
		'RSA-PSS-SHA2-384':'-SIGN-RSA-PSS-SHA384:-SIGN-RSA-PSS-RSAE-SHA384',
		'RSA-PSS-SHA2-512':'-SIGN-RSA-PSS-SHA512:-SIGN-RSA-PSS-RSAE-SHA512',
		'EDDSA-ED448':'-SIGN-EDDSA-ED448',
		'EDDSA-ED25519':'-SIGN-EDDSA-ED25519'
	}

	legacy_sign_map = {
		'DSA-SHA1':'+SIGN-DSA-SHA1',
		'RSA-SHA1':'+SIGN-RSA-SHA1'
	}

	cipher_not_map = {
		'AES-256-CTR':'',
		'AES-128-CTR':'',
		'AES-256-GCM':'-AES-256-GCM',
		'AES-128-GCM':'-AES-128-GCM',
		'AES-256-CCM':'-AES-256-CCM',
		'AES-128-CCM':'-AES-128-CCM',
		'AES-256-CBC':'-AES-256-CBC',
		'AES-128-CBC':'-AES-128-CBC',
		'CAMELLIA-256-GCM':'-CAMELLIA-256-GCM',
		'CAMELLIA-128-GCM':'-CAMELLIA-128-GCM',
		'CAMELLIA-256-CBC':'-CAMELLIA-256-CBC',
		'CAMELLIA-128-CBC':'-CAMELLIA-128-CBC',
		'CHACHA20-POLY1305':'-CHACHA20-POLY1305',
		'3DES-CBC':'-3DES-CBC',
		'RC4-128':'-ARCFOUR-128'
	}

	cipher_force_map = {
		'3DES-CBC':'+3DES-CBC',
		'RC4-128':'+ARCFOUR-128'
	}

	key_exchange_map = {
		'RSA':'+RSA',
		'ECDHE':'+ECDHE-RSA:+ECDHE-ECDSA',
		'DHE-RSA':'+DHE-RSA',
		'DHE-DSS':'+DHE-DSS',
		'PSK':'',
		'DHE-PSK':'',
		'ECDHE-PSK':''
	}

	protocol_not_map = {
		'SSL3.0':'-VERS-SSL3.0',
		'TLS1.0':'-VERS-TLS1.0',
		'TLS1.1':'-VERS-TLS1.1',
		'TLS1.2':'-VERS-TLS1.2',
		'TLS1.3':'-VERS-TLS1.3',
		'DTLS1.0':'-VERS-DTLS1.0',
		'DTLS1.2':'-VERS-DTLS1.2'
	}

	@classmethod
	def generate_config(cls, policy):
		s = 'SYSTEM=NONE'
		p = policy.enabled
		ip = policy.disabled

		if p['mac']:
			s = cls.append(s, '+MAC-ALL')
			for i in ip['mac']:
				try:
					s = cls.append(s, cls.mac_not_map[i])
				except KeyError:
					pass

		if p['group']:
			s = cls.append(s, '+GROUP-ALL')
			for i in ip['group']:
				try:
					s = cls.append(s, cls.group_not_map[i])
				except KeyError:
					pass

		if p['sign']:
			s = cls.append(s, '+SIGN-ALL')
			for i in ip['sign']:
				try:
					s = cls.append(s, cls.sign_not_map[i])
				except KeyError:
					pass
			for i in p['sign']:
				try:
					s = cls.append(s, cls.legacy_sign_map[i])
				except KeyError:
					pass

		if policy.integers['sha1_in_certs']:
			s = cls.append(s, '%VERIFY_ALLOW_SIGN_WITH_SHA1')

		if p['cipher']:
			s = cls.append(s, '+CIPHER-ALL')
			for i in ip['cipher']:
				try:
					s = cls.append(s, cls.cipher_not_map[i])
				except KeyError:
					pass
			for i in p['cipher']:
				try:
					s = cls.append(s, cls.cipher_force_map[i])
				except KeyError:
					pass

		for i in p['key_exchange']:
			try:
				s = cls.append(s, cls.key_exchange_map[i])
			except KeyError:
				pass

		if p['protocol']:
			s = cls.append(s, '+VERS-ALL:-VERS-DTLS0.9')
			for i in ip['protocol']:
				try:
					s = cls.append(s, cls.protocol_not_map[i])
				except KeyError:
					pass

		s = cls.append(s, '+COMP-NULL')

		# We cannot separate RSA strength from DH params.
		min_rsa_size = policy.integers['min_rsa_size']
		min_dh_size = policy.integers['min_dh_size']
		if min_dh_size <= 768 or min_rsa_size <= 768:
			s = cls.append(s, '%PROFILE_VERY_WEAK')
		elif min_dh_size <= 1024 or min_rsa_size <= 1024:
			s = cls.append(s, '%PROFILE_LOW')
		elif min_dh_size <= 2048 or min_rsa_size <= 2048:
			s = cls.append(s, '%PROFILE_MEDIUM')
		elif min_dh_size <= 3072 or min_rsa_size <= 3072:
			s = cls.append(s, '%PROFILE_HIGH')
		elif min_dh_size <= 8192 or min_rsa_size <= 8192:
			s = cls.append(s, '%PROFILE_ULTRA')
		else:
			s = cls.append(s, '%PROFILE_FUTURE')

		s += '\n'
		return s

	@classmethod
	def test_config(cls, config):
		if not os.access('/usr/bin/gnutls-cli', os.X_OK):
			return True

		fd, path = mkstemp()

		ret = 255
		try:
			with os.fdopen(fd, 'w') as f:
				f.write(config)
			try:
				ret = call('/usr/bin/gnutls-cli -l --priority $(cat ' + path +
					' | sed \'s/SYSTEM=//g\' | tr --delete \'\n\') >/dev/null',
					shell=True)
			except CalledProcessError:
				cls.eprint("/usr/bin/gnutls-cli: Execution failed")
		finally:
			os.unlink(path)

		if ret:
			cls.eprint("There is an error in gnutls generated policy")
			cls.eprint("Policy:\n%s" % config)
			return False
		return True
