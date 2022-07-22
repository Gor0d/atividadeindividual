#!/usr/libexec/platform-python

# SPDX-License-Identifier: LGPL-2.1-or-later

# Copyright (c) 2019 Red Hat, Inc.
# Copyright (c) 2019 Tomáš Mráz <tmraz@fedoraproject.org>

import sys
import argparse
import os
import subprocess
from tempfile import mkstemp
import glob
import warnings

import cryptopolicies
import cryptopolicies.validation

import policygenerators


warnings.formatwarning = lambda msg, category, *a, **kwa: \
	f'{category.__name__}: {str(msg).capitalize()}\n'


DEFAULT_PROFILE_DIR = '/usr/share/crypto-policies'
DEFAULT_BASE_DIR = '/etc/crypto-policies'
RELOAD_CMD_NAME = 'reload-cmds.sh'
FIPS_MODE_FLAG = '/proc/sys/crypto/fips_enabled'


def eprint(*args, **kwargs):
	print(*args, file=sys.stderr, **kwargs)


try:
	profile_dir = os.environ['profile_dir']
	cryptopolicies.UnscopedCryptoPolicy.SHARE_DIR = profile_dir
except KeyError:
	profile_dir = DEFAULT_PROFILE_DIR

try:
	base_dir = os.environ['base_dir']
	cryptopolicies.UnscopedCryptoPolicy.CONFIG_DIR = base_dir
except KeyError:
	base_dir = DEFAULT_BASE_DIR


local_dir = os.path.join(base_dir, 'local.d')
backend_config_dir = os.path.join(base_dir, 'back-ends')
state_dir = os.path.join(base_dir, 'state')

reload_cmd_path = os.path.join(profile_dir, RELOAD_CMD_NAME)


def parse_args():
	"Parse the command line"
	parser = argparse.ArgumentParser(allow_abbrev=False)
	group = parser.add_mutually_exclusive_group()
	group.add_argument('--set', nargs='?', default='', metavar='POLICY',
		help='set the policy POLICY')
	group.add_argument('--show', action='store_true',
		help='show the current policy from the configuration')
	group.add_argument('--is-applied', action='store_true',
		help='check whether the current policy is applied')
	parser.add_argument('--no-check', action='store_true',
		help=argparse.SUPPRESS)
	parser.add_argument('--no-reload', action='store_true',
		help='do not run the reload scripts when setting a policy')
	return parser.parse_args()


def is_applied():
	try:
		time1 = os.stat(os.path.join(state_dir, 'current')).st_mtime
		time2 = os.stat(os.path.join(base_dir, 'config')).st_mtime
	except OSError:
		sys.exit(77)

	if time1 >= time2:
		print("The configured policy is applied")
		sys.exit(0)
	print("The configured policy is NOT applied")
	sys.exit(1)


def setup_directories():
	try:
		os.makedirs(backend_config_dir)
		os.makedirs(state_dir)
	except OSError:
		pass


def fips_mode():
	try:
		with open(FIPS_MODE_FLAG) as f:
			return int(f.read()) > 0
	except OSError:
		return False


def safe_write(directory, filename, contents):
	(fd, path) = mkstemp(prefix=filename, dir=directory)
	os.write(fd, bytes(contents, 'utf-8'))
	os.fsync(fd)
	os.fchmod(fd, 0o644)
	try:
		os.rename(path, os.path.join(directory, filename))
	except OSError as e:
		os.unlink(path)
		os.close(fd)
		raise e
	finally:
		os.close(fd)


def safe_symlink(directory, filename, target):
	(fd, path) = mkstemp(prefix=filename, dir=directory)
	os.close(fd)
	os.unlink(path)
	os.symlink(target, path)
	try:
		os.rename(path, os.path.join(directory, filename))
	except OSError as e:
		os.unlink(path)
		raise e


def save_config(pconfig, cfgname, cfgdata, cfgdir, localdir, profiledir,
		policy_was_empty):
	local_cfg_path = os.path.join(localdir, cfgname + '-*.config')
	local_cfgs = sorted(glob.glob(local_cfg_path))
	local_cfg_present = False

	for lcfg in local_cfgs:
		if os.path.exists(lcfg):
			local_cfg_present = True

	profilepath = os.path.join(profiledir, str(pconfig), cfgname + '.txt')
	profilepath_exists = os.access(profilepath, os.R_OK)

	if not local_cfg_present and profilepath_exists:
		safe_symlink(cfgdir, cfgname + '.config', profilepath)
		return

	if profilepath_exists and not pconfig.subpolicies and policy_was_empty:
		# special case: if the policy has no directives, has files on disk,
		# and no subpolicy is used, but local.d modifications are present,
		# we'll concatenate the externally supplied policy with local.d# we'll concatenate the externally supplied policy with local.d
		with open(profilepath) as f_pre:
			cfgdata = f_pre.read()

	safe_write(cfgdir, cfgname + '.config', cfgdata)

	if local_cfg_present:
		cfgfile = os.path.join(cfgdir, cfgname + '.config')
		for lcfg in local_cfgs:
			try:
				with open(lcfg, 'r') as lf:
					local_data = lf.read()
			except OSError:
				eprint("Cannot read local policy file " + cfgname)
				continue

			try:
				with open(cfgfile, 'a') as cf:
					cf.write(local_data)
			except OSError:
				eprint("Error applying local configuration to " + cfgname)


class ProfileConfig:
	def __init__(self):
		self.policy = ''
		self.subpolicies = []

	def parse_string(self, s, subpolicy=False):
		l = s.upper().split(':')
		if l[0] and not subpolicy:
			self.policy = l[0]
			l = l[1:]
		l = [i for i in l if l]
		if subpolicy:
			self.subpolicies.append(l)
		else:
			self.subpolicies = l

	def parse_file(self, filename):
		subpolicy = False
		with open(filename) as f:
			for line in f:
				line = line.split('#', 1)[0]
				line = line.strip()
				if line:
					self.parse_string(line, subpolicy)
					subpolicy = True

	def remove_subpolicies(self, s):
		l = s.upper().split(':')
		self.subpolicies = [i for i in self.subpolicies if i not in l]

	def __str__(self):
		s = self.policy
		subs = ':'.join(self.subpolicies)
		if subs:
			s = s + ':' + subs
		return s

	def show(self):
		print(str(self))


def main():
	"The actual command implementation"
	cmdline = parse_args()

	if cmdline.is_applied:
		is_applied()
		sys.exit(0)

	err = 0

	setup_directories()

	pconfig = ProfileConfig()

	set_config = False

	configfile = os.path.join(base_dir, 'config')
	if os.access(configfile, os.R_OK):
		pconfig.parse_file(configfile)
	elif fips_mode():
		pconfig.parse_string('FIPS')
	else:
		pconfig.parse_file(os.path.join(profile_dir, 'default-config'))

	if cmdline.show:
		pconfig.show()
		sys.exit(0)

	profile = cmdline.set

	if profile:
		oldpolicy = pconfig.policy
		pconfig.parse_string(profile)
		set_config = True

		# FIPS profile is a special case
		if pconfig.policy != oldpolicy:
			if pconfig.policy == 'FIPS':
				eprint("Warning: Using 'update-crypto-policies --set FIPS' is not sufficient for")
				eprint("         FIPS compliance.")
				eprint("         Use 'fips-mode-setup --enable' command instead.")
			elif fips_mode():
				eprint("Warning: Using 'update-crypto-policies --set' in FIPS mode will make the system")
				eprint("         non-compliant with FIPS.")
				eprint("         It can also break the ssh access to the system.")
				eprint("         Use 'fips-mode-setup --disable' to disable the system FIPS mode.")

	if base_dir == DEFAULT_BASE_DIR:
		if not os.geteuid() == 0:
			eprint("You must be root to run update-crypto-policies.")
			sys.exit(1)

	try:
		cp = cryptopolicies.UnscopedCryptoPolicy(pconfig.policy,
			*pconfig.subpolicies)
	except cryptopolicies.validation.PolicyFileNotFoundError as ex:
		eprint(ex)
		sys.exit(1)
	except cryptopolicies.validation.PolicySyntaxError as ex:
		eprint(f'Errors found in policy, first one:  \n{ex}')
		sys.exit(1)

	print("Setting system policy to " + str(pconfig))

	generators = [g for g in dir(policygenerators) if 'Generator' in g]

	for g in generators:
		cls = policygenerators.__dict__[g]
		gen = cls()
		try:
			config = gen.generate_config(cp.scoped(gen.SCOPES))
		except LookupError:
			eprint('Error generating config for ' + gen.CONFIG_NAME)
			eprint('Keeping original configuration')
			err = 1

		try:
			save_config(pconfig, gen.CONFIG_NAME, config,
				backend_config_dir, local_dir, profile_dir,
				policy_was_empty=cp.is_empty())
		except OSError:
			eprint('Error saving config for ' + gen.CONFIG_NAME)
			eprint('Keeping original configuration')
			err = 1

	if set_config:
		try:
			safe_write(base_dir, 'config', str(pconfig) + '\n')
		except OSError:
			eprint('Error setting the current policy configuration')
			err = 3

	try:
		safe_write(state_dir, 'current', str(pconfig) + '\n')
	except OSError:
		eprint('Error updating current policy marker')
		err = 2

	try:
		safe_write(state_dir, 'CURRENT.pol', str(cp))
	except OSError:
		eprint('Error updating current policy dump')
		err = 2

	print("Note: System-wide crypto policies are applied on application start-up.")
	print("It is recommended to restart the system for the change of policies")
	print("to fully take place.")

	if not cmdline.no_reload:
		subprocess.call(['/bin/bash', reload_cmd_path])

	sys.exit(err)


# Entry point
if __name__ == "__main__":
	main()
