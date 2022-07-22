# SPDX-License-Identifier: LGPL-2.1-or-later

# Copyright (c) 2019 Red Hat, Inc.
# Copyright (c) 2019 Tomáš Mráz <tmraz@fedoraproject.org>

from subprocess import check_output, CalledProcessError
from tempfile import mkstemp
import os

from .configgenerator import ConfigGenerator


class BindGenerator(ConfigGenerator):
	CONFIG_NAME = 'bind'
	SCOPES = {'dnssec', 'bind'}

	RELOAD_CMD = 'systemctl try-reload-or-restart bind.service 2>/dev/null || :\n'

	sign_not_map = {
		'RSA-MD5':'RSAMD5',
		'DSA-SHA1':'DSA',
		'ECDSA-SHA1':'',
		'RSA-SHA1':'RSASHA1;\nNSEC3RSASHA1'
	}

	hash_not_map = {
		'MD5':'',
		'SHA1':'SHA-1',
		'GOST':'GOST',
		'SHA2-256':'SHA-256',
		'SHA2-384':'SHA-384'
	}

	@classmethod
	def generate_config(cls, policy):
		ip = policy.disabled
		sep = ';\n'

		cfg = 'disable-algorithms "." {\n'
		s = ''
		for i in ip['sign']:
			try:
				s = cls.append(s, cls.sign_not_map[i], sep)
			except KeyError:
				pass
		cfg += cls.append(s, '}', sep)

		cfg = cls.append(cfg, 'disable-ds-digests "." {\n', sep)
		s = ''
		for i in ip['hash']:
			try:
				s = cls.append(s, cls.hash_not_map[i], sep)
			except KeyError:
				pass
		cfg += cls.append(s, '};\n', sep)

		return cfg

	@classmethod
	def test_config(cls, config):
		fd, path = mkstemp()

		try:
			with os.fdopen(fd, 'w') as f:
				f.write('options {\n')
				f.write(config)
				f.write('\n};\n')
			try:
				_ = check_output(["/usr/sbin/named-checkconf", path])
			except CalledProcessError:
				cls.eprint("There is an error in bind generated policy")
				cls.eprint("Policy:\n%s" % config)
				return False
			except OSError:
				# Ignore missing check command
				pass
		finally:
			os.unlink(path)

		return True
