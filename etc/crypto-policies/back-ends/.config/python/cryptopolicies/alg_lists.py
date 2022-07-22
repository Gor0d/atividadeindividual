# SPDX-License-Identifier: LGPL-2.1-or-later

# Copyright (c) 2019 Red Hat, Inc.
# Copyright (c) 2019 Tomáš Mráz <tmraz@fedoraproject.org>

"""
Lists of algorithms and globbing among them.
"""

import fnmatch

from . import validation


ALL_CIPHERS = (
    'AES-256-GCM', 'AES-256-CCM',
    'AES-192-GCM', 'AES-192-CCM',
    'AES-128-GCM', 'AES-128-CCM',
    'CHACHA20-POLY1305',
    'CAMELLIA-256-GCM', 'CAMELLIA-128-GCM',
    'AES-256-CTR', 'AES-256-CBC',
    'AES-192-CTR', 'AES-192-CBC',
    'AES-128-CTR', 'AES-128-CBC',
    'CAMELLIA-256-CBC', 'CAMELLIA-128-CBC',
    '3DES-CBC', 'DES-CBC', 'RC4-40', 'RC4-128',
    'DES40-CBC', 'RC2-CBC', 'IDEA-CBC', 'SEED-CBC',
    'NULL',
)

ALL_MACS = (
    'AEAD', 'UMAC-128', 'HMAC-SHA1', 'HMAC-SHA2-256',
    'HMAC-SHA2-384', 'HMAC-SHA2-512', 'UMAC-64', 'HMAC-MD5',
)

ALL_HASHES = (
    'SHA2-256', 'SHA2-384', 'SHA2-512', 'SHA3-256', 'SHA3-384', 'SHA3-512',
    'SHA2-224', 'SHA1', 'MD5',
    'GOST',
)

# we disable curves <= 256 bits by default in Fedora
ALL_GROUPS = (
    'X25519', 'SECP256R1', 'SECP384R1', 'SECP521R1', 'X448',
    'FFDHE-1536', 'FFDHE-2048', 'FFDHE-3072', 'FFDHE-4096',
    'FFDHE-6144', 'FFDHE-8192', 'FFDHE-1024',
)

ALL_SIGN = (
    'RSA-MD5', 'RSA-SHA1', 'DSA-SHA1', 'ECDSA-SHA1',
    'RSA-SHA2-224', 'DSA-SHA2-224', 'ECDSA-SHA2-224',
    'RSA-SHA2-256', 'DSA-SHA2-256', 'ECDSA-SHA2-256', 'ECDSA-SHA2-256-FIDO',
    'RSA-SHA2-384', 'DSA-SHA2-384', 'ECDSA-SHA2-384',
    'RSA-SHA2-512', 'DSA-SHA2-512', 'ECDSA-SHA2-512',
    'RSA-SHA3-256', 'DSA-SHA3-256', 'ECDSA-SHA3-256',
    'RSA-SHA3-384', 'DSA-SHA3-384', 'ECDSA-SHA3-384',
    'RSA-SHA3-512', 'DSA-SHA3-512', 'ECDSA-SHA3-512',
    'EDDSA-ED25519', 'EDDSA-ED25519-FIDO', 'EDDSA-ED448',
    'RSA-PSS-SHA1', 'RSA-PSS-SHA2-224', 'RSA-PSS-SHA2-256',
    'RSA-PSS-SHA2-384', 'RSA-PSS-SHA2-512', 'RSA-PSS-RSAE-SHA1',
    'RSA-PSS-RSAE-SHA2-224', 'RSA-PSS-RSAE-SHA2-256',
    'RSA-PSS-RSAE-SHA2-384', 'RSA-PSS-RSAE-SHA2-512',
)


ALL_KEY_EXCHANGES = (
    'PSK', 'DHE-PSK', 'ECDHE-PSK', 'ECDHE', 'RSA',
    'DHE', 'DHE-RSA', 'DHE-DSS', 'EXPORT', 'ANON', 'DH', 'ECDH',
    'DHE-GSS', 'ECDHE-GSS',
)

# Order matters, see preprocess_text
TLS_PROTOCOLS = ('TLS1.3', 'TLS1.2', 'TLS1.1', 'TLS1.0', 'SSL3.0', 'SSL2.0')
DTLS_PROTOCOLS = ('DTLS1.2', 'DTLS1.0', 'DTLS0.9')
IKE_PROTOCOLS = ('IKEv2', 'IKEv1')
ALL_PROTOCOLS = TLS_PROTOCOLS + DTLS_PROTOCOLS + IKE_PROTOCOLS


ALL = {
    'cipher': ALL_CIPHERS,
    'group': ALL_GROUPS,
    'hash': ALL_HASHES,
    'key_exchange': ALL_KEY_EXCHANGES,
    'mac': ALL_MACS,
    'protocol': ALL_PROTOCOLS,
    'sign': ALL_SIGN,
}


def glob(pattern, alg_class):
    """
    Lists algorithms matching a glob, in order of appearance in ALL[alg_class].
    For more examples, refer to tests/unit/parsing/test_alg_lists.py
    >>> glob('RC4-*', 'cipher')
    ['RC4-40', 'RC4-128']
    """
    if alg_class not in ALL:
        raise validation.alg_lists.AlgorithmClassUnknownError(alg_class)

    r = fnmatch.filter(ALL[alg_class], pattern)
    if not r:
        raise validation.alg_lists.AlgorithmEmptyMatchError(pattern, alg_class)
    return r


def earliest_occurrence(needles, ordered_haystack):
    """
    >>> earliest_occurrence('test', 'abcdefghijklmnopqrstuvwxyz')
    'e'
    """
    intersection = [n for n in needles if n in ordered_haystack]
    if not intersection:
        return None
    indices = (ordered_haystack.index(n) for n in intersection)
    return ordered_haystack[min(indices)]


def min_tls_version(versions):
    """
    >>> min_tls_version(['SSL3.0', 'TLS1.2'])
    'SSL3.0'
    """
    return earliest_occurrence(versions, TLS_PROTOCOLS[::-1])


def min_dtls_version(versions):
    """
    >>> min_dtls_version(['DTLS1.2', 'DTLS1.0'])
    'DTLS1.0'
    """
    return earliest_occurrence(versions, DTLS_PROTOCOLS[::-1])


def max_tls_version(versions):
    """
    >>> max_tls_version(['SSL3.0', 'TLS1.2'])
    'TLS1.2'
    """
    return earliest_occurrence(versions, TLS_PROTOCOLS)


def max_dtls_version(versions):
    """
    >>> max_dtls_version(['DTLS1.2', 'DTLS1.0'])
    'DTLS1.2'
    """
    return earliest_occurrence(versions, DTLS_PROTOCOLS)
