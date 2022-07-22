#!/usr/libexec/platform-python

# SPDX-License-Identifier: LGPL-2.1-or-later

# Copyright (c) 2019 Red Hat, Inc.
# Copyright (c) 2019 Tomáš Mráz <tmraz@fedoraproject.org>

import argparse
import os
import sys
import warnings

import cryptopolicies

import policygenerators


RELOAD_CMD_NAME = 'reload-cmds.sh'


def eprint(*args, **kwargs):
	print(*args, file=sys.stderr, **kwargs)


def parse_args():
	"Parse the command line"
	parser = argparse.ArgumentParser(allow_abbrev=False)
	parser.add_argument('--flat', action='store_true',
		help='put all the generated files in a single directory')
	parser.add_argument('--test', action='store_true',
		help='compare the generated config file with the existing one')
	parser.add_argument('--policy', type=str, metavar='POLICY',
		help='generate the specified policy only')
	parser.add_argument('--reloadcmds', action='store_true',
		help='also save reload cmds into reload-cmds.sh script in output directory')
	parser.add_argument('--strict', action='store_true',
		help='fail on warnings')
	parser.add_argument('policydir',
		help='a directory with base policy definition files (*.pol)')
	parser.add_argument('outputdir',
		help='a target directory with generated config files')
	return parser.parse_args()


def save_config(cmdline, policy_name, config_name, config):
	if cmdline.flat:
		path = os.path.join(cmdline.outputdir, '{}-{}.txt'.format(policy_name, config_name))
	else:
		dirpath = os.path.join(cmdline.outputdir, policy_name)
		if not os.path.isdir(dirpath):
			try:
				os.mkdir(dirpath)
			except OSError:
				eprint('Cannot create directory for policy {}'.format(policy_name))
				return False
		path = os.path.join(dirpath, config_name + '.txt')

	if cmdline.test:
		try:
			with open(path, mode='r') as f:
				old_config = f.read()
			if old_config != config:
				eprint('Config for {} for policy {} differs from the existing one'.format(config_name, policy_name))
				return False
			return True
		except FileNotFoundError:
			pass
		except OSError:
			eprint('Error reading generated file {}'.format(path))
			return False

	print('Saving config for {} for policy {}'.format(config_name, policy_name))
	with open(path, mode='w') as f:
		f.write(config)
	print()
	return True


def build_policy(cmdline, policy_name, subpolicy_names=None):
	err = 0
	if subpolicy_names is None:
		subpolicy_names = []

	try:
		cp = cryptopolicies.UnscopedCryptoPolicy(policy_name,
			*subpolicy_names,*subpolicy_names,
			policydir=cmdline.policydir)
	except ValueError as e:  # TODO: catch specific thing
		eprint('Error: ' + str(e))
		return 1

	generators = [g for g in dir(policygenerators) if 'Generator' in g]

	for g in generators:
		cls = policygenerators.__dict__[g]
		gen = cls()
		config = gen.generate_config(cp.scoped(gen.SCOPES))

		if policy_name == 'EMPTY' or gen.test_config(config):
			try:
				name = ':'.join([policy_name, *subpolicy_names])
				if not save_config(cmdline, name, gen.CONFIG_NAME, config):
					err = 5
			except OSError:
				eprint('Error saving config for ' + gen.CONFIG_NAME)
				eprint('Keeping original configuration')
				err = 4
		else:
			eprint('Error testing config for ' + gen.CONFIG_NAME)
			err = 3
	return err


def save_reload_cmds(cmdline):
	err = 0

	generators = [g for g in dir(policygenerators) if 'Generator' in g]

	path = os.path.join(cmdline.outputdir, RELOAD_CMD_NAME)
	try:
		with open(path, mode='w') as f:
			for g in generators:
				cls = policygenerators.__dict__[g]
				f.write(cls.RELOAD_CMD)
	except OSError:
		eprint('Error saving reload cmds')
		err = 6
	return err


def main():
	"The actual command implementation"
	cmdline = parse_args()
	err = 0

	if cmdline.strict:
		warnings.filterwarnings("error")

	if cmdline.policy:
		(policy_name, *subpolicy_names) = filter(None, cmdline.policy.upper().split(':'))
		err = build_policy(cmdline, policy_name, subpolicy_names)
	else:
		with os.scandir(cmdline.policydir) as sd:
			for i in sd:
				if not i.name.startswith('.') and i.is_file():
					(policy_name, ext) = os.path.splitext(i.name)
					if ext == '.pol':
						err = build_policy(cmdline, policy_name)
						if err:
							break

	if not err and cmdline.reloadcmds:
		err = save_reload_cmds(cmdline)

	sys.exit(err)


# Entry point
if __name__ == "__main__":
	main()
