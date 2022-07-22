# SPDX-License-Identifier: LGPL-2.1-or-later

# Copyright (c) 2019 Red Hat, Inc.
# Copyright (c) 2019 Tomáš Mráz <tmraz@fedoraproject.org>

from .configgenerator import ConfigGenerator


class JavaGenerator(ConfigGenerator):
	CONFIG_NAME = 'java'
	SCOPES = {'tls', 'ssl', 'java-tls'}

	hash_not_map = {
		'MD2' :'MD2',
		'MD5' :'MD5',
		'SHA1':'SHA1',
		'SHA2-224':'SHA224',
		'SHA2-256':'SHA256',
		'SHA2-384':'SHA384',
		'SHA2-512':'SHA512',
		'SHA3-256':'SHA3_256',
		'SHA3-384':'SHA3_384',
		'SHA3-512':'SHA3_512',
		'GOST':''
	}

	cipher_not_map = {
		'AES-256-CTR':'',
		'AES-128-CTR':'',
		'CHACHA20-POLY1305':'',
		'CAMELLIA-256-GCM':'',
		'CAMELLIA-128-GCM':'',
		'CAMELLIA-256-CBC':'',
		'CAMELLIA-128-CBC':'',
		'AES-256-CBC':'AES_256_CBC',
		'AES-128-CBC':'AES_128_CBC',
		'AES-256-GCM':'AES_256_GCM',
		'AES-128-GCM':'AES_128_GCM',
		'AES-256-CCM':'AES_256_CCM',
		'AES-128-CCM':'AES_128_CCM',
		'RC4-128':'RC4_128',
		'RC4-40':'RC4_40',
		'RC2-CBC':'RC2',
		'DES-CBC':'DES_CBC',
		'DES40-CBC':'DES40_CBC',
		'3DES-CBC' :'3DES_EDE_CBC',
		'SEED-CBC' :'',
		'IDEA-CBC' :'',
		'NULL':''
	}

	cipher_legacy_map = {
		'RC4-128':'RC4_128',
		'3DES-CBC':'3DES_EDE_CBC',
	}

	key_exchange_not_map = {
		'EXPORT':'RSA_EXPORT, DHE_DSS_EXPORT, DHE_RSA_EXPORT, DH_DSS_EXPORT, DH_RSA_EXPORT',
		'DH':'DH_RSA, DH_DSS',
		'ANON':'DH_anon, ECDH_anon',
		'RSA':'TLS_RSA_WITH_AES_256_CBC_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_128_GCM_SHA256',
		'DHE-RSA':'DHE_RSA',
		'DHE-DSS':'DHE_DSS',
		'ECDHE':'ECDHE',
		'ECDH':'ECDH',
		'PSK':'',
		'DHE-PSK':'',
		'ECDHE-PSK':''
	}

	sign_not_map = {
		# we handle signature algorithms via disabled hashes
		'DSA-SHA1':'DSA',
		'RSA-SHA1':'',
		'ECDSA-SHA1':'',
		'RSA-MD5':''
	}

	protocol_not_map = {
		'SSL2.0':'SSLv2',
		'SSL3.0':'SSLv3',
		'TLS1.0':'TLSv1',
		'TLS1.1':'TLSv1.1',
		'TLS1.2':'TLSv1.2',
		'DTLS1.0':'',
		'DTLS1.2':''
	}

	mac_not_map = {
		'AEAD':'',
		'HMAC-MD5':'HmacMD5',
		'HMAC-SHA1':'HmacSHA1',
		'HMAC-SHA2-256':'HmacSHA256',
		'HMAC-SHA2-384':'HmacSHA384',
		'HMAC-SHA2-512':'HmacSHA512',
	}

	@classmethod
	def generate_config(cls, policy):
		p = policy.enabled
		ip = policy.disabled
		sep = ', '

		cfg = 'jdk.tls.ephemeralDHKeySize=' + str(policy.integers['min_dh_size']) + '\n'
		cfg += 'jdk.certpath.disabledAlgorithms='

		s = ''
		s = cls.append(s, 'MD2', sep)
		for i in ip['hash']:
			try:
				s = cls.append(s, cls.hash_not_map[i], sep)
			except KeyError:
				pass

		for i in ip['sign']:
			try:
				s = cls.append(s, cls.sign_not_map[i], sep)
			except KeyError:
				pass

		s = cls.append(s, 'RSA keySize < ' + str(policy.integers['min_rsa_size']), sep)
		cfg += s

		cfg += '\njdk.tls.disabledAlgorithms='

		s = ''
		s = cls.append(s, 'DH keySize < ' + str(policy.integers['min_dh_size']), sep)

		for i in ip['protocol']:
			try:
				s = cls.append(s, cls.protocol_not_map[i], sep)
			except KeyError:
				pass

		for i in ip['key_exchange']:
			try:
				s = cls.append(s, cls.key_exchange_not_map[i], sep)
			except KeyError:
				pass

		for i in ip['cipher']:
			try:
				s = cls.append(s, cls.cipher_not_map[i], sep)
			except KeyError:
				pass

		for i in ip['mac']:
			try:
				s = cls.append(s, cls.mac_not_map[i], sep)
			except KeyError:
				pass

		cfg += s

		cfg += '\njdk.tls.legacyAlgorithms='

		s = ''
		for i in p['cipher']:
			try:
				s = cls.append(s, cls.cipher_legacy_map[i], sep)
			except KeyError:
				pass

		cfg += s

		cfg += '\n'
		return cfg

	@classmethod
	def test_config(cls, config):  # pylint: disable=unused-argument
		return True
