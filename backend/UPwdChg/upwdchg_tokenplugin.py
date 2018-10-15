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
# DEPENDENCIES
#------------------------------------------------------------------------------

# UPwdChg
from UPwdChg import \
    Config, \
    TokenReader, \
    TokenWriter

# Standard
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
        self.__sFileConfig = None
        self.__oConfig = Config()


    def config(self, _sFileConfig):
        try:
            self.__oConfig.load(_sFileConfig)
            self.__sFileConfig = _sFileConfig
        except Exception as e:
            self._DEBUG('Failed to load configuration file')
            self._EXIT_ERROR('Internal error; please contact your system administrator')


    #------------------------------------------------------------------------------
    # METHODS
    #------------------------------------------------------------------------------

    #
    # Helpers
    #

    def _DEBUG(self, _lsMessages, _iDebugLevel = DEBUG_ERROR):
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
            sPrefix = 'ERROR'
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
        # Already configured (?)
        if self.__sFileConfig is not None:
            return

        # Check arguments
        if len(sys.argv) < 3:
            self._DEBUG('Missing argument(s); expected configuration and token files')
            self._EXIT_ERROR('Internal error; please contact your system administrator')

        # Configuration
        self.config(sys.argv[1])


    #
    # Getters
    #

    def _getToken(self, _sPrivateKey='backend', _sPublicKey='frontend'):
        # Configuration
        self._config()

        # Get token data
        oToken = TokenReader()
        oToken.config(self.__oConfig[_sPrivateKey]['private_key_file'], self.__oConfig[_sPublicKey]['public_key_file'])
        if oToken.readToken(sys.argv[2]):
            self._EXIT_ERROR('Internal error; please contact your system administrator')
        return oToken


    def _getTokenReader(self, _sPrivateKey='backend', _sPublicKey='frontend'):
        # Configuration
        self._config()

        # Token reader
        oTokenReader = TokenReader()
        oTokenReader.config(self.__oConfig[_sPrivateKey]['private_key_file'], self.__oConfig[_sPublicKey]['public_key_file'])
        return oTokenReader


    def _getTokenWriter(self, _sPrivateKey='backend', _sPublicKey='frontend'):
        # Configuration
        self._config()

        # Token writer
        oTokenWriter = TokenWriter()
        oTokenWriter.config(self.__oConfig[_sPrivateKey]['private_key_file'], self.__oConfig[_sPublicKey]['public_key_file'])
        return oTokenWriter
