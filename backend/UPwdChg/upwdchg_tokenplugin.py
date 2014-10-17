#!/usr/bin/env python
# -*- mode:python; tab-width:4; c-basic-offset:4; intent-tabs-mode:nil; -*-
# ex: filetype=python tabstop=4 softtabstop=4 shiftwidth=4 expandtab autoindent smartindent

#
# Universal Password Changer (UPwdChg)
# Copyright (C) 2014 Cedric Dufour <http://cedric.dufour.name>
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

# Modules
from UPwdChg import \
    TokenReader
import sys


#------------------------------------------------------------------------------
# CLASSES
#------------------------------------------------------------------------------

class TokenPlugin(TokenReader):
    """
    Universal Password Changer Token Processing Plugin
    """

    #------------------------------------------------------------------------------
    # CONSTRUCTORS / DESTRUCTOR
    #------------------------------------------------------------------------------

    def __init__( self, _sName, _bCritical = True ):
        TokenReader.__init__( self )

        # Fields
        self.__sName = _sName
        self.__bCritical = _bCritical
        if _bCritical:
            self.__sErrorPrefix = 'ERROR'
        else:
            self.__sErrorPrefix = 'WARNING'


    #------------------------------------------------------------------------------
    # METHODS
    #------------------------------------------------------------------------------

    #
    # Helpers
    #

    def _DEBUG( self, _lsMessages ):
        if not isinstance( _lsMessages, list ):
            _lsMessages = [ _lsMessages ]
        for __sMessage in _lsMessages:
            sys.stderr.write( '%s[%s]: %s\n' % ( self.__sErrorPrefix, self.__sName, __sMessage ) )

    def _EXIT_ERROR( self, _lsMessages ):
        if not isinstance( _lsMessages, list ):
            _lsMessages = [ _lsMessages ]
        for __sMessage in _lsMessages:
            sys.stdout.write( '%s[%s]: %s\n' % ( self.__sErrorPrefix, self.__sName, __sMessage ) )
        if self.__bCritical:
            sys.exit( 2 )
        else:
            sys.exit( 1 )

    def _EXIT_OK( self, _lsMessages ):
        if not isinstance( _lsMessages, list ):
            _lsMessages = [ _lsMessages ]
        for __sMessage in _lsMessages:
            sys.stdout.write( 'OK[%s]: %s\n' % ( self.__sName, __sMessage ) )
        sys.exit( 0 )


    #
    # Initialization
    #

    def _getToken( self ):
        # Check arguments
        if len( sys.argv ) < 3:
            self._DEBUG( 'Missing argument(s); expected token and RSA private key paths' )
            self._EXIT_ERROR( 'Internal error; please contact your system administrator' )

        # Get token data
        __oToken = TokenReader()
        if __oToken.read( sys.argv[1], sys.argv[2] ):
            self._EXIT_ERROR( 'Internal error; please contact your system administrator' )

        # Done
        return __oToken.getData()

