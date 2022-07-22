# SPDX-License-Identifier: LGPL-2.1-or-later

# Copyright (c) 2019 Red Hat, Inc.
# Copyright (c) 2019 Tomáš Mráz <tmraz@fedoraproject.org>

import collections
import enum
import fnmatch
import os
import re
import warnings

from . import alg_lists
from . import validation  # moved out of the way to not obscure the flow


# Defaults of integer property values (doubles as an allowlist)

INT_DEFAULTS = {k: 0 for k in (
    'arbitrary_dh_groups',
    'min_dh_size', 'min_dsa_size', 'min_rsa_size',
    'sha1_in_certs',
    'ssh_certs', 'ssh_etm',
)}


# Scopes (`@!ipsec`) and matching them

SCOPE_ANY = '*'

ALL_SCOPES = (  # defined explicitly to catch typos / globbing nothing
    'tls', 'ssl', 'openssl', 'nss', 'gnutls', 'java-tls',
    'ssh', 'openssh', 'openssh-server', 'openssh-client', 'libssh',
    'ipsec', 'ike', 'libreswan',
    'kerberos', 'krb5',
    'dnssec', 'bind',
)
DUMPABLE_SCOPES = {  # TODO: fix duplication, backends specify same things
    'bind': {'bind', 'dnssec'},
    'gnutls': {'gnutls', 'tls', 'ssl'},
    'java-tls': {'java-tls', 'tls', 'ssl'},
    'krb5': {'krb5', 'kerberos'},
    'libreswan': {'ipsec', 'ike', 'libreswan'},
    'libssh': {'libssh', 'openssh', 'ssh'},
    'nss': {'nss', 'tls', 'ssl'},
    'openssh-client': {'openssh-client', 'openssh', 'ssh'},
    'openssh-server': {'openssh-server', 'openssh', 'ssh'},
    'openssl': {'openssl', 'tls', 'ssl'},
}


class ScopeSelector:
    def __init__(self, pattern=SCOPE_ANY):
        """
        Initialize a scope selector.
        An example would be `ssh` in `ciphers@ssh = -NULL`.
        When openssh backend will request the configuration,
        it'll offer (`{'ssh', 'openssh'}`) as scopes
        and the rule above will be taken into account.
        Both patterns and scopes are cast to lowercase.
        For more examples, refer to tests/unit/parsing/test_scope_selector.py
        >>> ss = ScopeSelector('!{SSH,IPsec}')
        >>> ss.matches({'ipsec', 'libreswan'})
        False
        >>> ss.matches({'tls', 'openssl'})
        True
        """
        self.pattern = pattern = pattern.lower()
        self._positive = not pattern.startswith('!')
        p = pattern if self._positive else pattern[1:]

        validation.scope.illegal_characters(p, original_pattern=self.pattern)
        validation.scope.curly_brackets(p, original_pattern=self.pattern)

        self._globs = p[1:-1].split(',') if p.startswith('{') else [p]

        validation.scope.resulting_globs(self._globs, ALL_SCOPES,
                                         original_pattern=self.pattern)

    def __str__(self):
        return f'<ScopeSelector pattern={repr(self.pattern)}>'

    def matches(self, scopes):
        """
        Checks whether ScopeSelector matches one of the scopes.
        For more examples, refer to tests/unit/parsing/test_scope_selector.py
        >>> ScopeSelector('{SSH,IPsec}').matches({'ipsec', 'libreswan'})
        True
        >>> ScopeSelector('!{SSH,IPsec}').matches({'ipsec', 'libreswan'})
        False
        """
        if self.pattern == SCOPE_ANY:  # matches even an empty set
            return True
        scopes = [s.lower() for s in scopes]
        assert all(s in ALL_SCOPES for s in scopes)  # supplied by backends
        if self._positive:
            return any(fnmatch.filter(scopes, g) for g in self._globs)
        return all(not fnmatch.filter(scopes, g) for g in self._globs)


# Operations: interpreting right hand sides of (sub)policy files

class Operation(enum.Enum):
    """
    An operation that comes with the right-hand value of the directive.
    """
    RESET = 1     # cipher =
    PREPEND = 2   # cipher = +NULL
    APPEND = 3    # cipher = NULL+
    OMIT = 4      # cipher = -NULL
    SET_INT = 5   # sha1_in_certs = 0; setting to something that's all digits


def parse_rhs(rhs, prop_name):
    """
    Parses right-hand parts of the directives
    into lists of operation/value pairs.
    For more examples, refer to tests/unit/test_parsing.py
    >>> parse_rhs('', 'cipher')
    [(<Operation.RESET: 1>, None)]
    >>> parse_rhs('IDEA-CBC SEED-CBC', 'cipher')
    [(<Operation.RESET: 1>, None),
     (<Operation.APPEND: 3>, 'IDEA-CBC'),
     (<Operation.APPEND: 3>, 'SEED-CBC')]
    >>> # 3DES-CBC gets prepended last for higher prio
    >>> parse_rhs('+*DES-CBC', 'cipher')
    [(<Operation.PREPEND: 2>, 'DES-CBC'),
     (<Operation.PREPEND: 2>, '3DES-CBC')]
    """
    def differential(v):
        return v.startswith('+') or v.endswith('+') or v.startswith('-')

    if rhs.isdigit():
        if prop_name not in alg_lists.ALL and prop_name in INT_DEFAULTS:
            return [(Operation.SET_INT, int(rhs))]
        elif prop_name in alg_lists.ALL:
            raise validation.rules.NonIntPropertyIntValueError(prop_name)
        else:
            assert prop_name not in alg_lists.ALL
            assert prop_name not in INT_DEFAULTS
            # pass for now, it's gonna be caught as non-existing algclass
    else:
        if prop_name in INT_DEFAULTS:
            raise validation.rules.IntPropertyNonIntValueError(prop_name)

    values = rhs.split()

    if not any(differential(v) for v in values):  # Setting something anew
        values = sum([alg_lists.glob(v, prop_name) for v in values], [])
        return ([(Operation.RESET, None)]
                + [(Operation.APPEND, v) for v in values])
    elif all(differential(v) for v in values):  # Modifying an existing list
        operations = []
        for value in values:
            if value.startswith('+'):
                op = Operation.PREPEND
                unglob = alg_lists.glob(value[1:], prop_name)[::-1]
            elif value.endswith('+'):
                op = Operation.APPEND
                unglob = alg_lists.glob(value[:-1], prop_name)[::-1]
            else:
                assert value.startswith('-')
                op = Operation.OMIT
                unglob = alg_lists.glob(value[1:], prop_name)
            operations.extend([(op, v) for v in unglob])
        return operations
    else:  # Forbidden to mix them on one line
        raise validation.rules.MixedDifferentialNonDifferentialError(rhs)


# Directives: interpreting lines of (sub)policy files

Directive = collections.namedtuple('Directive', (
    'prop_name', 'scope', 'operation', 'value'
))


def parse_line(line):
    """
    Parses configuration lines into tuples of directives.
    For more examples, refer to tests/unit/test_parsing.py
    >>> parse_line('cipher@TLS = RC4* NULL')
    [Directive(prop_name='cipher', scope='tls',
               operation=<Operation.RESET: 1>, value=None),
     Directive(prop_name='cipher', scope='tls',
               operation=<Operation.APPEND: 3>, value='RC4-40'),
     Directive(prop_name='cipher', scope='tls',
               operation=<Operation.APPEND: 3>, value='RC4-128'),
     Directive(prop_name='cipher', scope='tls',
               operation=<Operation.APPEND: 3>, value='NULL')]
    """
    if not line.strip():
        return []
    validation.rules.count_equals_signs(line)

    lhs, rhs = line.split('=')
    lhs, rhs = lhs.strip(), rhs.strip()
    validation.rules.empty_lhs(lhs, line)

    prop_name, scope = lhs.split('@', 1) if '@' in lhs else (lhs, SCOPE_ANY)

    return [Directive(prop_name=prop_name, scope=scope.lower(),
                      operation=operation, value=value)
            for operation, value in parse_rhs(rhs, prop_name)]


def syntax_check_line(line, warn=False):
    try:
        l = parse_line(line)
        for d in l:
            ScopeSelector(d.scope)  # attempt parsing
    except validation.PolicySyntaxError as ex:
        if not warn:
            raise
        warnings.warn(ex)


class PolicySyntaxDeprecationWarning(FutureWarning):
    def __init__(self, deprecated, replacement):
        replacement = replacement.replace('\n', ' and ')
        msg = f'option {deprecated} is deprecated'
        msg += f', please rewrite your rules using {replacement}; '
        msg += 'be advised that it is not always a 1-1 replacement'
        super().__init__(msg)


def preprocess_text(text):
    r"""
    Preprocesses text before parsing.
    Fixes line breaks, handles backwards compatibility.
    >>> preprocess_text('cipher = c1 \\ \nc2#x')
    'cipher = c1 c2'
    >>> with warnings.catch_warnings():
    ...     warnings.simplefilter("ignore")
    ...     preprocess_text('ike_protocol = IKEv2')
    'protocol@IKE = IKEv2'
    >>> with warnings.catch_warnings():
    ...     warnings.simplefilter("ignore")
    ...     preprocess_text('min_tls_version=TLS1.3')
    'protocol@TLS = -SSL2.0 -SSL3.0 -TLS1.0 -TLS1.1 -TLS1.2'
    """
    text = re.sub(r'#.*', '', text)
    text = text.replace('=', ' = ')
    text = '\n'.join((l.strip() for l in text.split('\n')))
    text = text.replace('\\\n', '')
    text = '\n'.join((l.strip() for l in text.split('\n')))
    text = '\n'.join((re.sub(r'\s+', ' ', l) for l in text.split('\n')))
    text = re.sub('\n+', '\n', text).strip()

    if re.findall(r'\bprotocol\s*=', text):
        warnings.warn(PolicySyntaxDeprecationWarning('protocol',
                                                     'protocol@TLS'))

    POSTFIX_REPLACEMENTS = {
        'tls_cipher': 'cipher@TLS',
        'ssh_cipher': 'cipher@SSH',
        'ssh_group': 'group@SSH',
        'ike_protocol': 'protocol@IKE',
    }
    for fr, to in POSTFIX_REPLACEMENTS.items():
        regex = r'\b' + fr + r'\s*=(.*)'
        ms = re.findall(regex, text)
        if ms:
            warnings.warn(PolicySyntaxDeprecationWarning(fr, to))
        text = re.sub(regex, '', text)
        for m in ms:
            text += f'\n\n{to} ={m}'
    text = re.sub('\n+', '\n', text).strip()

    PLAIN_REPLACEMENTS = {
        'sha1_in_dnssec = 0':
            'hash@DNSSec = -SHA1\nsign@DNSSec = -RSA-SHA1 -ECDSA-SHA1',
        'sha1_in_dnssec = 1':
            'hash@DNSSec = SHA1+\nsign@DNSSec = RSA-SHA1+ ECDSA-SHA1+',
    }
    for fr, to in PLAIN_REPLACEMENTS.items():
        regex = r'\b' + fr + r'\b'
        if re.search(regex, text):
            warnings.warn(PolicySyntaxDeprecationWarning(fr, to))
        text = re.sub(regex, to, text)

    dtls_versions = list(alg_lists.DTLS_PROTOCOLS[::-1])
    while dtls_versions:
        neg = " ".join(("-" + v for v in dtls_versions[:-1]))
        text = re.sub(r'\bmin_dtls_version = ' + dtls_versions[-1] + r'\b',
                      f'protocol@TLS = {neg}' if neg else '', text)
        dtls_versions.pop()
    text = re.sub(r'\bmin_dtls_version = 0\b', '', text)

    tls_versions = list(alg_lists.TLS_PROTOCOLS[::-1])
    while tls_versions:
        neg = " ".join(("-" + v for v in tls_versions[:-1]))
        text = re.sub(r'\bmin_tls_version = ' + tls_versions[-1] + r'\b',
                      f'protocol@TLS = {neg}' if neg else '', text)
        tls_versions.pop()
    text = re.sub(r'\bmin_tls_version = 0\b', '', text)

    return text


# Finally, constructing a policy

class ScopedPolicy:
    """
    An entity constructing lists of what's `.enabled` and what's `.disabled`
    when the given scopes are active.
    >>> sp = ScopedPolicy(parse_line('cipher@TLS = RC4* NULL'), {'tls'})
    >>> 'AES-256-GCM' in sp.disabled['cipher']
    True
    >>> sp.enabled['cipher']
    ['RC4-40', 'RC4-128', 'NULL']
    >>> ScopedPolicy(parse_line('min_dh_size=2048')).integers['min_dh_size']
    2048
    """
    def __init__(self, directives, relevant_scopes=None):
        relevant_scopes = relevant_scopes or set()
        self.integers = INT_DEFAULTS.copy()
        self.enabled = {prop_name: [] for prop_name in alg_lists.ALL}

        for directive in directives:
            # TODO: validate that the target exists
            ss = ScopeSelector(directive.scope)
            if ss.matches(relevant_scopes):
                if directive.operation == Operation.RESET:
                    self.enabled[directive.prop_name] = []
                elif directive.operation == Operation.APPEND:
                    enabled = self.enabled[directive.prop_name]
                    if directive.value not in enabled:
                        enabled.append(directive.value)
                elif directive.operation == Operation.PREPEND:
                    enabled = self.enabled[directive.prop_name]
                    # in case of duplicates, remove the latter, lower-prio ones
                    if directive.value in enabled:
                        enabled.remove(directive.value)
                    enabled.insert(0, directive.value)
                elif directive.operation == Operation.OMIT:
                    self.enabled[directive.prop_name] = [
                        e for e in self.enabled[directive.prop_name]
                        if e != directive.value
                    ]
                else:
                    assert directive.operation == Operation.SET_INT
                    self.integers[directive.prop_name] = directive.value
        assert len(self.enabled) == len(set(self.enabled))

        self.disabled = {prop_name: [e for e in alg_lists.ALL[prop_name]
                                     if e not in self.enabled[prop_name]]
                         for prop_name in alg_lists.ALL}

    @property
    def min_tls_version(self):
        return alg_lists.min_tls_version(self.enabled['protocol'])

    @property
    def max_tls_version(self):
        return alg_lists.max_tls_version(self.enabled['protocol'])

    @property
    def min_dtls_version(self):
        return alg_lists.min_dtls_version(self.enabled['protocol'])

    @property
    def max_dtls_version(self):
        return alg_lists.max_dtls_version(self.enabled['protocol'])


# Locating policy files

def lookup_file(policyname, fname, paths):
    for d in paths:
        p = os.path.join(d, fname)
        if os.access(p, os.R_OK):
            return p
    raise validation.PolicyFileNotFoundError(policyname, fname, paths)


# main class

class UnscopedCryptoPolicy:
    CONFIG_DIR = '/etc/crypto-policies'

    SHARE_DIR = '/usr/share/crypto-policies'

    def __init__(self, policy_name, *subpolicy_names, policydir=None):
        self.policydir = policydir
        self.policyname = ':'.join((policy_name,) + subpolicy_names)

        self.lines = []

        directives = self.read_policy_file(policy_name)
        for subpolicy_name in subpolicy_names:
            directives += self.read_policy_file(subpolicy_name, subpolicy=True)
        self._directives = directives

    def is_empty(self):
        return not self._directives

    def scoped(self, scopes=None):
        return ScopedPolicy(self._directives, scopes or {})

    def read_policy_file(self, name, subpolicy=False):
        pdir = self.policydir or 'policies'
        if subpolicy:
            pdir = os.path.join(pdir, 'modules')
        p = lookup_file(name,
                        name + ('.pol' if not subpolicy else '.pmod'), (
                            os.path.curdir,
                            pdir,
                            os.path.join(self.CONFIG_DIR, pdir),
                            os.path.join(self.SHARE_DIR, pdir),
                        ))
        # TODO: error handling
        with open(p) as f:
            text = f.read()
        text = preprocess_text(text)
        lines = text.split('\n')
        for l in lines:  # display several warnings at once
            syntax_check_line(l, warn=True)
        for l in lines:  # crash
            syntax_check_line(l)
        return sum([parse_line(l) for l in lines], [])

    def __str__(self):
        def fmt(key, value):
            s = ' '.join(value) if isinstance(value, list) else str(value)
            return f'{key} = {s}'.rstrip() + '\n'

        generic_scoped = self.scoped()
        s = f'# Policy {self.policyname} dump\n'
        s += '#\n'
        s += '# Do not parse the contents of this file with automated tools,\n'
        s += '# it is provided for review convenience only.\n'
        s += '#\n'
        s += '# Baseline values for all scopes:\n'
        generic_all = {**generic_scoped.enabled, **generic_scoped.integers}
        for prop_name, value in generic_all.items():
            s += fmt(prop_name, value)
        anything_scope_specific = False
        for scope_name, scope_set in DUMPABLE_SCOPES.items():
            specific_scoped = self.scoped(scopes=scope_set)
            specific_all = {**specific_scoped.enabled,
                            **specific_scoped.integers}
            for prop_name, value in specific_all.items():
                if value != generic_all[prop_name]:
                    if not anything_scope_specific:
                        s += ('# Scope-specific properties '
                              'derived for select backends:\n')
                        anything_scope_specific = True
                    s += fmt(f'{prop_name}@{scope_name}', value)
        if not anything_scope_specific:
            s += '# No scope-specific properties found.\n'
        return s
