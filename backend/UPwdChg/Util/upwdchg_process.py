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
# ... deb: python-argparse
from UPwdChg import \
    UPWDCHG_VERSION, \
    UPWDCHG_DEFAULT_FILE_KEY_PRIVATE, \
    UPWDCHG_DEFAULT_FILE_KEY_PUBLIC, \
    UPWDCHG_DEFAULT_DIR_PLUGINS, \
    UPWDCHG_DEFAULT_FILE_RANDOM, \
    TokenReader
import argparse as AP
import os
import stat
import subprocess as SP
import sys
from tempfile import \
    mkstemp


#------------------------------------------------------------------------------
# CLASSES
#------------------------------------------------------------------------------

class Process:
    """
    Universal Password Changer Token Process
    """

    #------------------------------------------------------------------------------
    # CONSTRUCTORS / DESTRUCTOR
    #------------------------------------------------------------------------------

    def __init__(self):
        # Fields
        self._bDebug = False
        self.config()

    def config(self,
        _sFileKeyPrivate = UPWDCHG_DEFAULT_FILE_KEY_PRIVATE,
        _sFileKeyPublic = UPWDCHG_DEFAULT_FILE_KEY_PUBLIC,
        _sDirPlugins = UPWDCHG_DEFAULT_DIR_PLUGINS,
        _sFileRandom = UPWDCHG_DEFAULT_FILE_RANDOM,
        ):
        self._sFileKeyPrivate = _sFileKeyPrivate
        self._sFileKeyPublic = _sFileKeyPublic
        self._sDirPlugins = _sDirPlugins
        self._sFileRandom = _sFileRandom


    #------------------------------------------------------------------------------
    # METHODS
    #------------------------------------------------------------------------------

    def processToken(self, _sFileToken, _sTokenType = None, _oStdErr = None):
        """
        Process token (validation and password change)
        Returns the highest plugin's return code along the list of each plugin's output.
        """

        # Redirect standard error (?)
        if _oStdErr:
            sys.stderr = _oStdErr

        # Initialize
        lsOutputs = list()

        # Reading token from stdin (?)
        hFileTmp = None
        if _sFileToken == '-':
            try:
                (hFileTmp, _sFileToken) = mkstemp()
                for sLine in sys.stdin:
                    os.write(hFileTmp, sLine)
                os.close(hFileTmp)
            except Exception as e:
                sys.stderr.write('ERROR[Process]: Failed to store token to temporary file; %s\n' % str(e))
                raise RuntimeError('failed to store token to temporary file; %s' % str(e))

        # Retrieve token type
        if _sTokenType is None:
            oToken = TokenReader()
            oToken.config(self._sFileKeyPrivate, self._sFileKeyPublic)
            iReturn = oToken.readToken(_sFileToken)
            if iReturn:
                raise RuntimeError('failed to read token file (error=%d); %s' % (iReturn, _sFileToken))
            _sTokenType = oToken.getType()
        if self._bDebug:
            sys.stderr.write('DEBUG[Process]: Token type; %s\n' % _sTokenType)

        # List plugins
        lsFilesPlugin = self.getPlugins(_sTokenType)
        if not len(lsFilesPlugin):
            if self._bDebug:
                sys.stderr.write('DEBUG[Process]: No processing plugin(s)\n')

        # Plugins processing
        iReturn = 0
        for sFilePlugin in lsFilesPlugin:
            if self._bDebug:
                sys.stderr.write('DEBUG[Process]: Token processing plugin; %s\n' % sFilePlugin)
            try:
                oPopen = SP.Popen([sFilePlugin, _sFileToken, self._sFileKeyPrivate, self._sFileKeyPublic, self._sFileRandom], stdout=SP.PIPE, stderr=SP.PIPE)
                (sStdOut, sStdErr) = oPopen.communicate()
                iReturn = max(iReturn, oPopen.returncode)
                lsOutputs.append(sStdOut)
                if sStdErr:
                    sys.stderr.write(sStdErr)
                if iReturn > 1:
                    break
            except Exception as e:
                sys.stderr.write('ERROR[Process]: Failed to process token; %s\n' % str(e))
                lsOutputs.append('ERROR[UPwdChg]: Internal error; please contact your system administrator')

        # Clean-up token temporary file
        if hFileTmp:
            try:
                os.remove(_sFileToken)
            except Exception as e:
                sys.stderr.write('ERROR[Process]: Failed to delete token temporary file; %s\n' % str(e))

        # Done
        return (iReturn, lsOutputs)


    def getPlugins(self, _sTokenType):
        """
        Retrieve token processing plugins list; returns a (sorted) list of each plugin's path or None is case of failure.
        """

        # Initialize
        iModeExec = stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH
        lsFilesPlugin = list()

        # List plugins
        if self._sDirPlugins is not None:
            try:
                sDirPlugins = self._sDirPlugins.replace('%{type}', _sTokenType)
                for sFile in os.listdir(sDirPlugins):
                    sFile = sDirPlugins+os.sep+sFile
                    if os.path.isfile(sFile) and (os.stat(sFile).st_mode & iModeExec):
                        lsFilesPlugin.append(sFile)
            except Exception as e:
                sys.stderr.write('ERROR[Process]: Failed to retrieve plugins list\n; %s' % str(e))
                raise RuntimeError('failed to retrieve plugins list; %s' % str(e))
            lsFilesPlugin.sort()

        # Done
        return lsFilesPlugin


class ProcessMain(Process):
    """
    Universal Password Changer Token Process Main Executable
    """

    #------------------------------------------------------------------------------
    # CONSTRUCTORS / DESTRUCTOR
    #------------------------------------------------------------------------------

    def __init__(self):
        Process.__init__(self)

        # Fields
        self.__oArgumentParser = None
        self.__oArguments = None

        # Initialization
        self.__initArgumentParser()


    def __initArgumentParser(self):
        """
        Creates the arguments parser (and help generator)
        """

        # Create argument parser
        self.__oArgumentParser = AP.ArgumentParser(sys.argv[0].split(os.sep)[-1])

        # ... token file
        self.__oArgumentParser.add_argument(
            'token', type=str,
            metavar='<file>',
            default='-', nargs='?',
            help='Path to token file (default:stdin)')

        # ... RSA private key file
        self.__oArgumentParser.add_argument(
            '-Kv', '--key_private', type=str,
            metavar='<file>',
            default=UPWDCHG_DEFAULT_FILE_KEY_PRIVATE,
            help='Path to RSA private key file (PEM format; default:%s)' % UPWDCHG_DEFAULT_FILE_KEY_PRIVATE)

        # ... RSA public key file
        self.__oArgumentParser.add_argument(
            '-Ku', '--key_public', type=str,
            metavar='<file>',
            default=UPWDCHG_DEFAULT_FILE_KEY_PUBLIC,
            help='Path to RSA public key file (PEM format; default:%s)' % UPWDCHG_DEFAULT_FILE_KEY_PUBLIC)

        # ... plugins path
        self.__oArgumentParser.add_argument(
            '-Dp', '--dir_plugins', type=str,
            metavar='<directory>',
            default=UPWDCHG_DEFAULT_DIR_PLUGINS,
            help='Path to plugins directory (default:%s)' % UPWDCHG_DEFAULT_DIR_PLUGINS.replace('%','%%'))

        # ... PRNG seed source
        self.__oArgumentParser.add_argument(
            '-r', '--random', type=str,
            metavar='<file>',
            default=UPWDCHG_DEFAULT_FILE_RANDOM,
            help='Random number generator seed source (default:%s)' % UPWDCHG_DEFAULT_FILE_RANDOM)

        # ... debug
        self.__oArgumentParser.add_argument(
            '-d', '--debug', action='store_true',
            default=False,
            help='Enable debugging messages')

        # ... version
        self.__oArgumentParser.add_argument(
            '-v', '--version', action='version',
            version=('UPwdChg - %s - Cedric Dufour <http://cedric.dufour.name>\n' % UPWDCHG_VERSION))


    def __initArguments(self, _aArguments = None):
        """
        Parses the command-line arguments; returns a non-zero exit code in case of failure.
        """

        # Parse arguments
        if _aArguments is None: _aArguments = sys.argv
        try:
            self.__oArguments = self.__oArgumentParser.parse_args()
        except Exception, e:
            self.__oArguments = None
            sys.stderr.write('ERROR[ProcessMain]: Failed to parse arguments; %s\n' % str(e))
            return 1

        return 0


    #------------------------------------------------------------------------------
    # METHODS
    #------------------------------------------------------------------------------

    def execute(self):
        """
        Executes; returns a non-zero exit code in case of failure.
        """

        # Initialize

        # ... arguments
        iReturn = self.__initArguments()
        if iReturn:
            return iReturn

        # Configure processing
        self._bDebug = self.__oArguments.debug
        self.config(
            self.__oArguments.key_private,
            self.__oArguments.key_public,
            self.__oArguments.dir_plugins,
            self.__oArguments.random
            )

        # Process token
        try:
            (iReturn, lsOutputs) = self.processToken(self.__oArguments.token)
            for sOutput in lsOutputs:
                sys.stdout.write('%s' % sOutput)
        except RuntimeError:
            return 10

        # Done
        return 10+iReturn if iReturn else 0
