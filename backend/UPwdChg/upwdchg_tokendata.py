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
import json as JSON
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

    def __init__(self):
        # Fields
        self.__sEncoding = 'utf-8'
        self._dData = None
        self._sData = None


    #------------------------------------------------------------------------------
    # METHODS
    #------------------------------------------------------------------------------

    def setEncoding(self, _sEncoding):
        """
        Sets the (input/output) data encoding (default:UTF-8)
        """

        self.__sEncoding = _sEncoding


    def setData_PasswordChange(self, _suUsername, _suPasswordOld, _suPasswordNew):
        """
        Sets the token data
        """

        self._dData = { \
            'type': 'password-change', \
            'timestamp': unicode(strftime('%Y-%m-%dT%H:%M:%SZ', gmtime()), self.__sEncoding), \
            'username': _suUsername if isinstance(_suUsername, unicode) else _suUsername.decode(self.__sEncoding), \
            'password-old': _suPasswordOld if isinstance(_suPasswordOld, unicode) else _suPasswordOld.decode(self.__sEncoding), \
            'password-new': _suPasswordNew if isinstance(_suPasswordNew, unicode) else _suPasswordNew.decode(self.__sEncoding), \
        }
        self._sData = None


    def getData(self, _bAsJson=False):
        """
        Returns the token (unicode) data (dictionary), mapping:
         'type': 'password-change'
         'timestamp': token creation timestamp
         'username': user name
         'password-old': old password
         'password-new': new password
        Or the corresponding JSON (string), if specified
        """

        if _bAsJson:
            if self._sData is None:
                self._sData = JSON.dumps(self._dData, indent=4)
            return self._sData
        return self._dData


    def getType(self):
        """
        Returns the token type (string)
        """

        return self._dData['type']
