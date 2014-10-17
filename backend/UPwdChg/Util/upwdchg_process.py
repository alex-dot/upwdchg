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
# ... deb: python-argparse
from UPwdChg import \
    UPWDCHG_VERSION, \
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

    def __init__( self ):
        pass


    #------------------------------------------------------------------------------
    # METHODS
    #------------------------------------------------------------------------------

    def processToken( self, _sFileToken, _sFilePrivateKey, _lsFilesPlugin, _oStdErr = None ):
        """
        Process token (validation and password change); returns a list of each plugin's output or None is case of failure.
        """

        # Redirect standard error (?)
        if _oStdErr:
            sys.stderr = _oStdErr

        # Initialize
        __lsOutputs = list()

        # Reading token from stdin (?)
        __hFileTmp = None
        if _sFileToken == '-':
            try:
                ( __hFileTmp, _sFileToken ) = mkstemp()
                for __sLine in sys.stdin:
                    os.write( __hFileTmp, __sLine )
                os.close( __hFileTmp )
            except Exception as e:
                sys.stderr.write( 'ERROR[Process]: Failed to store token to temporary file; %s\n' % str( e ) )
                return None

        # Plugins processing
        for __sFilePlugin in _lsFilesPlugin:
            try:
                __oPopen = SP.Popen( [ __sFilePlugin, _sFileToken, _sFilePrivateKey ], stdout=SP.PIPE, stderr=SP.PIPE )
                ( __sStdOut, __sStdErr ) = __oPopen.communicate()
                __lsOutputs.append( __sStdOut )
                if __sStdErr:
                    sys.stderr.write( __sStdErr )
                if __oPopen.returncode > 1:
                    break
            except Exception as e:
                sys.stderr.write( 'ERROR[Process]: Failed to validate password change; %s\n' % str( e ) )
                __lsOutputs = None

        # Clean-up token temporary file
        if __hFileTmp:
            try:
                os.remove( _sFileToken )
            except Exception as e:
                sys.stderr.write( 'ERROR[Process]: Failed to delete token temporary file; %s\n' % str( e ) )

        # Done
        return __lsOutputs


    def getPlugins( self, _sDirPlugins ):
        """
        Retrieve token processing pugins list; returns a (sorted) list of each plugin's path or None is case of failure.
        """

        # Initialize
        __iModeExec = stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH
        __lsFilesPlugin = list()

        # List plugins
        if _sDirPlugins is not None:
            try:
                for __sFile in os.listdir( _sDirPlugins ):
                    __sFile = _sDirPlugins.rstrip( os.sep )+os.sep+__sFile
                    if os.path.isfile( __sFile ) and ( os.stat( __sFile ).st_mode & __iModeExec ):
                        __lsFilesPlugin.append( __sFile )
            except Exception as e:
                sys.stderr.write( 'ERROR[Process]: Failed to retrieve plugins list\n; %s' % str( e ) )
                return None
        if not len( __lsFilesPlugin ):
            return None
        __lsFilesPlugin.sort()

        # Done
        return __lsFilesPlugin


class ProcessMain(Process):
    """
    Universal Password Changer Token Process Main Executable
    """

    #------------------------------------------------------------------------------
    # CONSTRUCTORS / DESTRUCTOR
    #------------------------------------------------------------------------------

    def __init__( self ):
        Process.__init__( self )

        # Fields
        self.__oArgumentParser = None
        self.__oArguments = None

        # Initialization
        self.__initArgumentParser()


    def __initArgumentParser( self ):
        """
        Creates the arguments parser (and help generator)
        """

        # Create argument parser
        self.__oArgumentParser = AP.ArgumentParser( sys.argv[0].split( os.sep )[-1] )

        # ... token file
        self.__oArgumentParser.add_argument(
            'token', type=str,
            metavar='<token-file>',
            default='-', nargs='?',
            help='Path to token file (default:stdin)' )

        # ... RSA private key file
        self.__oArgumentParser.add_argument(
            '-Rk', '--key_private', type=str,
            metavar='<key-file>',
            default='/etc/upwdchg/private.pem',
            help='Path to RSA private key file (PEM format; /etc/upwdchg/private.pem)' )

        # ... plugins path
        self.__oArgumentParser.add_argument(
            '-P', '--plugins', type=str,
            metavar='<plugins-dir>',
            default='/etc/upwdchg/backend/plugins.d',
            help='Path to plugins directory' )

        # ... version
        self.__oArgumentParser.add_argument(
            '-v', '--version', action='version',
            version=( 'UPwdChg - %s - Cedric Dufour <http://cedric.dufour.name>\n' % UPWDCHG_VERSION ) )


    def __initArguments( self, _aArguments = None ):
        """
        Parses the command-line arguments; returns a non-zero exit code in case of failure.
        """

        # Parse arguments
        if _aArguments is None: _aArguments = sys.argv
        try:
            self.__oArguments = self.__oArgumentParser.parse_args()
        except Exception, e:
            self.__oArguments = None
            sys.stderr.write( 'ERROR[ProcessMain]: Failed to parse arguments; %s\n' % str( e ) )
            return 1

        return 0


    #------------------------------------------------------------------------------
    # METHODS
    #------------------------------------------------------------------------------

    def execute( self ):
        """
        Executes; returns a non-zero exit code in case of failure.
        """

        # Initialize

        # ... arguments
        __iReturn = self.__initArguments()
        if __iReturn:
            return __iReturn

        # List plugins
        __lsFilesPlugin = self.getPlugins( self.__oArguments.plugins )
        if __lsFilesPlugin is None:
            sys.stderr.write( 'ERROR[ProcessMain]: No processing plugin found\n' )
            return 1

        # Process token
        __lsOutputs = self.processToken( self.__oArguments.token, self.__oArguments.key_private, __lsFilesPlugin )
        if __lsOutputs is None:
            return 1
        for __sOutput in __lsOutputs:
            sys.stdout.write( '%s' % __sOutput )

        # Done
        return 0


