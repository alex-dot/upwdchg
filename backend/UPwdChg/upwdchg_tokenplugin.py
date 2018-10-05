#!/usr/bin/env python
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

# Modules
from UPwdChg import \
    UPWDCHG_DEFAULT_FILE_KEY_PRIVATE, \
    UPWDCHG_DEFAULT_FILE_KEY_PUBLIC, \
    UPWDCHG_DEFAULT_FILE_RANDOM, \
    TokenReader, \
    TokenWriter
import sys


#------------------------------------------------------------------------------
# CLASSES
#------------------------------------------------------------------------------

class TokenPlugin:
    """
    Universal Password Changer Token Processing Plugin
    """

    #------------------------------------------------------------------------------
    # CONSTANTS
    #------------------------------------------------------------------------------

    DEBUG_ERROR=0
    DEBUG_WARNING=1
    DEBUG_INFO=2
    DEBUG_NOTICE=3
    DEBUG_TRACE=4


    #------------------------------------------------------------------------------
    # CONSTRUCTORS / DESTRUCTOR
    #------------------------------------------------------------------------------

    def __init__(self, _sName, _bCritical = True, _iDebugLevel = DEBUG_ERROR):
        # Fields
        self.__sName = _sName
        self.__bCritical = _bCritical
        self.__iDebugLevel = _iDebugLevel
        if _bCritical:
            self.__sErrorPrefix = 'ERROR'
        else:
            self.__sErrorPrefix = 'WARNING'
        self.config()

    def config(self,
        _sFileKeyPrivate = UPWDCHG_DEFAULT_FILE_KEY_PRIVATE,
        _sFileKeyPublic = UPWDCHG_DEFAULT_FILE_KEY_PUBLIC,
        _sFileRandom = UPWDCHG_DEFAULT_FILE_RANDOM,
        ):
        self._sFileKeyPrivate = _sFileKeyPrivate
        self._sFileKeyPublic = _sFileKeyPublic
        self._sFileRandom = _sFileRandom


    #------------------------------------------------------------------------------
    # METHODS
    #------------------------------------------------------------------------------

    #
    # Helpers
    #

    def _DEBUG(self, _lsMessages, _iDebugLevel = None):
        if _iDebugLevel > self.__iDebugLevel:
            return
        if _iDebugLevel == self.DEBUG_TRACE:
            sPrefix = 'TRACE'
        elif _iDebugLevel == self.DEBUG_NOTICE:
            sPrefix = 'NOTICE'
        elif _iDebugLevel == self.DEBUG_INFO:
            sPrefix = 'INFO'
        elif _iDebugLevel == self.DEBUG_WARNING:
            sPrefix = 'WARNING'
        elif _iDebugLevel == self.DEBUG_ERROR:
            sPrefix = 'WARNING'
        else:
            sPrefix = self.__sErrorPrefix
        if not isinstance(_lsMessages, list):
            _lsMessages = [ _lsMessages ]
        for sMessage in _lsMessages:
            sys.stderr.write('%s[%s]: %s\n' % (sPrefix, self.__sName, sMessage))

    def _EXIT_ERROR(self, _lsMessages):
        if not isinstance(_lsMessages, list):
            _lsMessages = [ _lsMessages ]
        for sMessage in _lsMessages:
            sys.stdout.write('%s[%s]: %s\n' % (self.__sErrorPrefix, self.__sName, sMessage))
        if self.__bCritical:
            sys.exit(2)
        else:
            sys.exit(1)

    def _EXIT_OK(self, _lsMessages):
        if not isinstance(_lsMessages, list):
            _lsMessages = [ _lsMessages ]
        for sMessage in _lsMessages:
            sys.stdout.write('OK[%s]: %s\n' % (self.__sName, sMessage))
        sys.exit(0)


    #
    # Initialization
    #

    def _config(self):
        # Check arguments
        if len(sys.argv) < 5:
            self._DEBUG('Missing argument(s); expected token, RSA keys and random source paths')
            self._EXIT_ERROR('Internal error; please contact your system administrator')

        # Configuration
        self.config(sys.argv[2], sys.argv[3], sys.argv[4])


    #
    # Getters
    #

    def _getToken(self):
        # Configuration
        self._config()

        # Get token data
        oToken = TokenReader()
        oToken.config(self._sFileKeyPrivate, self._sFileKeyPublic)
        if oToken.readToken(sys.argv[1]):
            self._EXIT_ERROR('Internal error; please contact your system administrator')
        return oToken

    def _getTokenReader(self):
        # Configuration
        self._config()

        # Token reader
        oTokenReader = TokenReader()
        oTokenReader.config(self._sFileKeyPrivate, self._sFileKeyPublic)
        return oTokenReader

    def _getTokenWriter(self):
        # Configuration
        self._config()

        # Token writer
        oTokenWriter = TokenWriter()
        oTokenWriter.config(self._sFileKeyPrivate, self._sFileKeyPublic, self._sFileRandom)
        return oTokenWriter

