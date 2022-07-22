# SPDX-License-Identifier: LGPL-2.1-or-later

# Copyright (c) 2021 Red Hat, Inc.

class PolicySyntaxError(ValueError, UserWarning):
    pass


class PolicyFileNotFoundError(FileNotFoundError):
    def __init__(self, pname, fname, paths):
        super().__init__(f'Unknown policy `{pname}`: '
                         f'file `{fname}` not found in ({", ".join(paths)})')
