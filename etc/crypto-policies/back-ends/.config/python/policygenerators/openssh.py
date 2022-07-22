# SPDX-License-Identifier: LGPL-2.1-or-later

# Copyright (c) 2019 Red Hat, Inc.
# Copyright (c) 2019 Tomáš Mráz <tmraz@fedoraproject.org>

from subprocess import call, CalledProcessError
from tempfile import mkstemp

import os

from .configgenerator import ConfigGenerator


class OpenSSHGenerator(ConfigGenerator):
	_FORMAT_STRING = ''

	cipher_map = {
		'AES-256-GCM':'aes256-gcm@openssh.com',
		'AES-256-CTR':'aes256-ctr',
		'AES-192-GCM':'',  # not supported
		'AES-192-CTR':'aes192-ctr',
		'AES-128-GCM':'aes128-gcm@openssh.com',
		'AES-128-CTR':'aes128-ctr',
		'CHACHA20-POLY1305':'chacha20-poly1305@openssh.com',
		'CAMELLIA-256-GCM':'',
		'AES-256-CCM':'',
		'AES-192-CCM':'',
		'AES-128-CCM':'',
		'CAMELLIA-128-GCM':'',
		'AES-256-CBC':'aes256-cbc',
		'AES-192-CBC':'aes192-cbc',
		'AES-128-CBC':'aes128-cbc',
		'CAMELLIA-256-CBC':'',
		'CAMELLIA-128-CBC':'',
		'RC4-128':'',
		'DES-CBC':'',
		'CAMELLIA-128-CTS':'',
		'3DES-CBC':'3des-cbc'
	}

	mac_map_etm = {
		'HMAC-MD5':'hmac-md5-etm@openssh.com',
		'UMAC-64':'umac-64-etm@openssh.com',
		'UMAC-128':'umac-128-etm@openssh.com',
		'HMAC-SHA1':'hmac-sha1-etm@openssh.com',
		'HMAC-SHA2-256':'hmac-sha2-256-etm@openssh.com',
		'HMAC-SHA2-512':'hmac-sha2-512-etm@openssh.com'
	}

	mac_map = {
		'HMAC-MD5':'hmac-md5',
		'UMAC-64':'umac-64@openssh.com',
		'UMAC-128':'umac-128@openssh.com',
		'HMAC-SHA1':'hmac-sha1',
		'HMAC-SHA2-256':'hmac-sha2-256',
		'HMAC-SHA2-512':'hmac-sha2-512'
	}

	kx_map = {
		'ECDHE-SECP521R1-SHA2-512':'ecdh-sha2-nistp521',
		'ECDHE-SECP384R1-SHA2-384':'ecdh-sha2-nistp384',
		'ECDHE-SECP256R1-SHA2-256':'ecdh-sha2-nistp256',
		'ECDHE-X25519-SHA2-256':'curve25519-sha256,curve25519-sha256@libssh.org',
		'DHE-FFDHE-1024-SHA1':'diffie-hellman-group1-sha1',
		'DHE-FFDHE-2048-SHA1':'diffie-hellman-group14-sha1',
		'DHE-FFDHE-2048-SHA2-256':'diffie-hellman-group14-sha256',
		'DHE-FFDHE-4096-SHA2-512':'diffie-hellman-group16-sha512',
		'DHE-FFDHE-8192-SHA2-512':'diffie-hellman-group18-sha512',
	}

	gx_map = {
		'DHE-SHA1':'diffie-hellman-group-exchange-sha1',
		'DHE-SHA2-256':'diffie-hellman-group-exchange-sha256',
	}

	gss_kx_map = {
		'DHE-GSS-SHA1':'gss-gex-sha1-',
		'DHE-GSS-FFDHE-1024-SHA1':'gss-group1-sha1-',
		'DHE-GSS-FFDHE-2048-SHA1':'gss-group14-sha1-',
		'DHE-GSS-FFDHE-2048-SHA2-256':'gss-group14-sha256-',
		'ECDHE-GSS-SECP256R1-SHA2-256':'gss-nistp256-sha256-',
		'ECDHE-GSS-X25519-SHA2-256':'gss-curve25519-sha256-',
		'DHE-GSS-FFDHE-4096-SHA2-512':'gss-group16-sha512-',
	}

	sign_map = {
		'RSA-SHA1':'ssh-rsa',
		'DSA-SHA1':'ssh-dss',
		'RSA-SHA2-256':'rsa-sha2-256',
		'RSA-SHA2-512':'rsa-sha2-512',
		'ECDSA-SHA2-256':'ecdsa-sha2-nistp256',
		'ECDSA-SHA2-384':'ecdsa-sha2-nistp384',
		'ECDSA-SHA2-512':'ecdsa-sha2-nistp521',
		'EDDSA-ED25519':'ssh-ed25519',
	}

	sign_map_certs = {
		'RSA-SHA1':'ssh-rsa-cert-v01@openssh.com',
		'DSA-SHA1':'ssh-dss-cert-v01@openssh.com',
		'RSA-SHA2-256':'rsa-sha2-256-cert-v01@openssh.com',
		'RSA-SHA2-512':'rsa-sha2-512-cert-v01@openssh.com',
		'ECDSA-SHA2-256':'ecdsa-sha2-nistp256-cert-v01@openssh.com',
		'ECDSA-SHA2-384':'ecdsa-sha2-nistp384-cert-v01@openssh.com',
		'ECDSA-SHA2-512':'ecdsa-sha2-nistp521-cert-v01@openssh.com',
		'EDDSA-ED25519':'ssh-ed25519-cert-v01@openssh.com',
	}

	@classmethod
	def generate_options(cls, policy, local_kx_map, local_gss_kx_map, do_host_key):
		p = policy.enabled
		cfg = ''
		sep = ','

		s = ''
		for i in p['cipher']:
			try:
				s = cls.append(s, cls.cipher_map[i], sep)
			except KeyError:
				pass

		if s:
			cfg += cls._FORMAT_STRING.format('Ciphers', s)

		s = ''
		if policy.integers['ssh_etm']:
			for i in p['mac']:
				try:
					s = cls.append(s, cls.mac_map_etm[i], sep)
				except KeyError:
					pass
		for i in p['mac']:
			try:
				s = cls.append(s, cls.mac_map[i], sep)
			except KeyError:
				pass

		if s:
			cfg += cls._FORMAT_STRING.format('MACs', s)

		s = ''
		gss = ''
		for kx in p['key_exchange']:
			for h in p['hash']:
				if policy.integers['arbitrary_dh_groups']:
					try:
						val = cls.gx_map[kx + '-' + h]
						s = cls.append(s, val, sep)
					except KeyError:
						pass
					try:
						val = local_gss_kx_map[kx + '-' + h]
						gss = cls.append(gss, val, sep)
					except KeyError:
						pass
				for g in p['group']:
					try:
						val = local_kx_map[kx + '-' + g + '-' + h]
						s = cls.append(s, val, sep)
					except KeyError:
						pass
					try:
						val = local_gss_kx_map[kx + '-' + g + '-' + h]
						gss = cls.append(gss, val, sep)
					except KeyError:
						pass

		if gss:
			cfg += cls._FORMAT_STRING.format('GSSAPIKexAlgorithms', gss)
		else:
			cfg += cls._FORMAT_STRING.format('GSSAPIKeyExchange', 'no')

		if s:
			cfg += cls._FORMAT_STRING.format('KexAlgorithms', s)

		s = ''
		for i in p['sign']:
			try:
				s = cls.append(s, cls.sign_map[i], sep)
			except KeyError:
				pass
			if policy.integers['ssh_certs'] == 1:
				try:
					s = cls.append(s, cls.sign_map_certs[i], sep)
				except KeyError:
					pass

		if s:
			# As OpenSSH currently ignores existing known host
			# entries with this setting we cannot use it on client.
			# Otherwise we could break existing users.
			if do_host_key:
				cfg += cls._FORMAT_STRING.format('HostKeyAlgorithms', s)
			cfg += cls._FORMAT_STRING.format('PubkeyAcceptedKeyTypes', s)

		s = ''
		for i in p['sign']:
			try:
				s = cls.append(s, cls.sign_map[i], sep)
			except KeyError:
				pass

		if s:
			cfg += cls._FORMAT_STRING.format('CASignatureAlgorithms', s)

		return cfg


class OpenSSHClientGenerator(OpenSSHGenerator):
	CONFIG_NAME = 'openssh'
	SCOPES = {'ssh', 'openssh', 'openssh-client'}

	_FORMAT_STRING = '{0} {1}\n'

	@classmethod
	def generate_config(cls, policy):
		local_kx_map = dict(cls.kx_map)
		local_gss_kx_map = dict(cls.gss_kx_map)

		return cls.generate_options(policy, local_kx_map, local_gss_kx_map, False)

	@classmethod
	def test_config(cls, config):
		if not os.access('/usr/bin/ssh', os.X_OK):
			return True

		fd, path = mkstemp()

		ret = 255
		try:
			with os.fdopen(fd, 'w') as f:
				f.write(config)
			try:
				ret = call('/usr/bin/ssh -G -F ' + path +
					' bogus654_server >/dev/null',
					shell=True)
			except CalledProcessError:
				cls.eprint("/usr/bin/ssh: Execution failed")
		finally:
			os.unlink(path)

		if ret:
			cls.eprint("There is an error in OpenSSH generated policy")
			cls.eprint("Policy:\n%s" % config)
			return False
		return True


class OpenSSHServerGenerator(OpenSSHGenerator):
	CONFIG_NAME = 'opensshserver'
	SCOPES = {'ssh', 'openssh', 'openssh-server'}

	# We need restart here, since systemd needs to pick up new command line options
	RELOAD_CMD = 'systemctl try-restart sshd.service 2>/dev/null || :\n'

	_FORMAT_STRING = '-o{0}={1} '

	@classmethod
	def generate_config(cls, policy):
		# Difference from client, keep group1 disabled on server
		local_kx_map = dict(cls.kx_map)
		local_gss_kx_map = dict(cls.gss_kx_map)
		del local_kx_map['DHE-FFDHE-1024-SHA1']
		del local_gss_kx_map['DHE-GSS-FFDHE-1024-SHA1']

		cfg = cls.generate_options(policy, local_kx_map, local_gss_kx_map, True)
		cfg = cfg.rstrip()
		return 'CRYPTO_POLICY=\'' + cfg + '\''

	@classmethod
	def _test_setup(cls):
		_fd, path = mkstemp()
		os.unlink(path)
		ret = 255
		try:
			ret = call('/usr/bin/ssh-keygen -t rsa -b 2048 -f ' + path +
				' -N "" >/dev/null',
				shell=True)
		except CalledProcessError:
			cls.eprint("/usr/bin/ssh-keygen: Execution failed")

		if ret:
			cls.eprint("SSH Keygen failed when testing OpenSSH server policy")
			return ''
		return path

	@classmethod
	def _test_cleanup(cls, path):
		if path:
			os.unlink(path)

	@classmethod
	def test_config(cls, config):
		if not os.access('/usr/sbin/sshd', os.X_OK):
			return True

		host_key_filename = cls._test_setup()
		if not host_key_filename:
			return False

		fd, path = mkstemp()

		ret = 255
		try:
			with os.fdopen(fd, 'w') as f:
				f.write(config)
			try:
				ret = call('/usr/bin/bash -c \'source ' + path +
					' && /usr/sbin/sshd -T $CRYPTO_POLICY -h ' +
					host_key_filename +
					' -f /dev/null\' >/dev/null',
					shell=True)
			except CalledProcessError:
				cls.eprint("/usr/sbin/sshd: Execution failed")
		finally:
			os.unlink(path)
			cls._test_cleanup(host_key_filename)

		if ret:
			cls.eprint("There is an error in OpenSSH server generated policy")
			cls.eprint("Policy:\n%s" % config)
			return False
		return True
