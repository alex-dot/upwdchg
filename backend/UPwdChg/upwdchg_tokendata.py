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
from time import gmtime, strftime


#------------------------------------------------------------------------------
# CLASSES
#------------------------------------------------------------------------------

class TokenData:
    """
    Universal Password Changer Token Data
    """

    #------------------------------------------------------------------------------
    # CONSTRUCTORS / DESTRUCTOR
    #------------------------------------------------------------------------------

    def __init__( self ):
        # Fields
        self.__sEncoding = 'utf-8'
        self._uTimestamp = None
        self._uUsername = None
        self._uPasswordOld = None
        self._uPasswordNew = None


    #------------------------------------------------------------------------------
    # METHODS
    #------------------------------------------------------------------------------

    def setEncoding( self, _sEncoding ):
        """
        Sets the (input/output) data encoding (default:UTF-8)
        """

        self.__sEncoding = _sEncoding


    def setData( self, _suUsername, _suPasswordOld, _suPasswordNew ):
        """
        Sets the token data
        """

        self._uTimestamp = unicode( strftime( '%Y-%m-%dT%H:%M:%SZ', gmtime() ), self.__sEncoding )
        if isinstance( _suUsername, unicode ):
            self._uUsername = _suUsername
        else:
            self._uUsername = _suUsername.decode( self.__sEncoding )
        if isinstance( _suPasswordOld, unicode ):
            self._uPasswordOld = _suPasswordOld
        else:
            self._uPasswordOld = _suPasswordOld.decode( self.__sEncoding )
        if isinstance( _suPasswordNew, unicode ):
            self._uPasswordNew = _suPasswordNew
        else:
            self._uPasswordNew = _suPasswordNew.decode( self.__sEncoding )


    def getData( self ):
        """
        Returns the token (unicode) data (dictionary), mapping:
         'timestamp': token creation timestamp
         'username': user name
         'password-old': old password
         'password-new': new password
        """

        return {
            'timestamp' : self._uTimestamp,
            'username' : self._uUsername,
            'password-old' : self._uPasswordOld,
            'password-new' : self._uPasswordNew,
        }

