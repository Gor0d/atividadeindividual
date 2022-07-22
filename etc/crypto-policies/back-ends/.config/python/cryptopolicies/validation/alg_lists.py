# SPDX-License-Identifier: LGPL-2.1-or-later

# Copyright (c) 2021 Red Hat, Inc.

from .general import PolicySyntaxError


class AlgorithmClassSyntaxError(PolicySyntaxError):
    pass


class AlgorithmClassUnknownError(AlgorithmClassSyntaxError):
    def __init__(self, alg_class):
        # The wording follows the previous versions
        super().__init__(f'Unknown policy property: `{alg_class}`')


class AlgorithmEmptyMatchError(AlgorithmClassSyntaxError):
    def __init__(self, glob, alg_class):
        # The wording follows the previous versions
        super().__init__(f'Bad value of policy property `{alg_class}`: '
                         f'`{glob}`')
