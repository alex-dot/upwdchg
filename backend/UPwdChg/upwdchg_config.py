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
    UPWDCHG_CONFIGSPEC

# Extra
# ... deb: python3-configobj
import configobj as CO
import validate as VA

# Standard
import sys


#------------------------------------------------------------------------------
# CLASSES
#------------------------------------------------------------------------------

class Config:
    """
    Universal Password Changer Configuration
    """

    #------------------------------------------------------------------------------
    # CONSTRUCTORS / DESTRUCTOR
    #------------------------------------------------------------------------------

    def __init__(self):
        # Fields
        self.__oConfigObj = None


    #------------------------------------------------------------------------------
    # METHODS
    #------------------------------------------------------------------------------

    def load(self, _sFileConfig):
        """
        Loads configuration settings.
        """

        # Load configuration settings
        try:
            self.__oConfigObj = CO.ConfigObj(_sFileConfig, configspec=UPWDCHG_CONFIGSPEC, file_error=True)
        except Exception as e:
            self.__oConfigObj = None
            sys.stderr.write('ERROR[Config]: Failed to load configuration from file; %s\n' % str(e))
            raise RuntimeError('failed to load configuration from file; %s' % str(e))

        # ... and validate it
        oValidator = VA.Validator()
        oValidatorResult = self.__oConfigObj.validate(oValidator)
        if oValidatorResult != True:
            sys.stderr.write('ERROR[Config]: Invalid configuration data\n')
            for(lSectionList, sKey, _) in CO.flatten_errors(self.__oConfigObj, oValidatorResult):
                if sKey is not None:
                    sys.stderr.write(' > Invalid value/pair (%s:%s)\n' % (', '.join(lSectionList), sKey))
                else:
                    sys.stderr.write(' > Missing/incomplete section (%s)\n' % ', '.join(lSectionList))
            raise RuntimeError('invalid configuration data')


    def toString(self, _sPath=None, _dConfig=None, _sPrefix=None):
        """
        Dump configuration settings (as a string).
        """

        sOutput = ''
        if not _dConfig:
            _dConfig = self.__oConfigObj
        if not _sPath:
            lKeys = list(_dConfig.keys())
        else:
            lPath = _sPath.split('.')
            sKey = lPath[0].replace('*', '')
            lKeys = [sKey] if sKey else list(_dConfig.keys())
            _sPath = '.'.join(lPath[1:])
        for sKey in lKeys:
            if sKey not in _dConfig.keys():
                continue
            if isinstance(_dConfig[sKey], dict):
                sOutput += self.toString(_sPath, _dConfig[sKey], sKey)
            else:
                sName = _sPrefix+'_'+sKey if _sPrefix else sKey
                sValue = _dConfig[sKey]
                if sValue is None:
                    sValue = ''
                elif isinstance(sValue, bool):
                    sValue = '1' if sValue else '0'
                elif isinstance(sValue, str):
                    sValue = "'%s'" % sValue
                sOutput += '%s=%s\n' % (sName, sValue)
        return sOutput


    #------------------------------------------------------------------------------
    # OPERATORS
    #------------------------------------------------------------------------------

    def __getitem__(self, _sIndex):
        return self.__oConfigObj[_sIndex]

    def __str__(self):
        return self.toString()
