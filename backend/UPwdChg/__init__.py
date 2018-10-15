# -*- mode:python; tab-width:4; c-basic-offset:4; intent-tabs-mode:nil; -*-
# ex: filetype=python tabstop=4 softtabstop=4 shiftwidth=4 expandtab autoindent smartindent

#
# Universal Password Changer (UPwdChg)
# Copyright (C) 2014-2018 Cedric Dufour <http://cedric.dufour.name>
# Author: Cedric Dufour <http://cedric.dufour.name>
#
# The Universal Password Changer (UPwdChg) is free software:
# you can redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, Version 3.
#
# The Universal Password Changer (UPwdChg) is distributed in the hope
# that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# See the GNU General Public License for more details.
#
# SPDX-License-Identifier: GPL-3.0
# License-Filename: LICENSE/GPL-3.0.txt
#

#------------------------------------------------------------------------------
# CONSTANTS
#------------------------------------------------------------------------------

UPWDCHG_VERSION = 'devel'
UPWDCHG_CONFIGSPEC = 'upwdchg.conf.spec'
UPWDCHG_ENCODING = 'utf-8'
UPWDCHG_PUBLIC_ALGO = 'rsa'
UPWDCHG_CIPHER_ALGO = 'aes_256_cbc'
UPWDCHG_CIPHER_KEY_LENGTH = 32
UPWDCHG_CIPHER_IV_LENGTH = 16
UPWDCHG_DIGEST_ALGO = 'sha256'
UPWDCHG_PWHASH_METHOD = 'pbkdf2'
UPWDCHG_PWHASH_ALGO = 'sha256'
UPWDCHG_PWHASH_ITERATIONS = 10000
UPWDCHG_IDHASH_METHOD = 'hash'
UPWDCHG_IDHASH_ALGO = 'sha256'


#------------------------------------------------------------------------------
# DEPENDENCIES
#------------------------------------------------------------------------------

# UPwdChg
from .upwdchg_config import Config
from .upwdchg_tokendata import TokenData
from .upwdchg_tokenreader import TokenReader
from .upwdchg_tokenwriter import TokenWriter
from .upwdchg_tokenplugin import TokenPlugin
