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
    TokenReader, \
    TokenWriter
import argparse as AP
import getpass
import os
import sys


#------------------------------------------------------------------------------
# CLASSES
#------------------------------------------------------------------------------

class Token:
    """
    Universal Password Changer Token Reader/Writer
    """

    #------------------------------------------------------------------------------
    # CONSTRUCTORS / DESTRUCTOR
    #------------------------------------------------------------------------------

    def __init__(self):
        pass


    #------------------------------------------------------------------------------
    # METHODS
    #------------------------------------------------------------------------------

    def writeToken_PasswordChange(self, _sFileToken, _sFilePublicKey, _sFileRandom,
        _sUsername = None, _sPasswordNew = None, _sPasswordOld = None, _bPasswordOldPrompt = False,
        _sEncoding = None):
        """
        Write a 'password-change' token; returns a non-zero exit code in case of failure.
        """

        # Token data

        # ... username
        sUsername = _sUsername
        while not sUsername:
            sUsername = raw_input('Username: ')

        # ... password (old)
        sPasswordOld = _sPasswordOld
        while _bPasswordOldPrompt and not sPasswordOld:
            sPassword_confirm = None
            while sPassword_confirm is None or sPasswordOld != sPassword_confirm:
                if sPassword_confirm is not None:
                    sys.stdout.write('Password Mismatch! Please try again...\n')
                sPasswordOld = getpass.getpass('Old Password: ')
                sPassword_confirm = getpass.getpass('Old Password (confirm): ')

        # ... password (new)
        sPasswordNew = _sPasswordNew
        while not sPasswordNew:
            sPassword_confirm = None
            while sPassword_confirm is None or sPasswordNew != sPassword_confirm:
                if sPassword_confirm is not None:
                    sys.stdout.write('Password Mismatch! Please try again...\n')
                sPasswordNew = getpass.getpass('New Password: ')
                sPassword_confirm = getpass.getpass('New Password (confirm): ')

        # Write token
        oToken = TokenWriter()
        if _sEncoding:
            oToken.setEncoding(_sEncoding)
        oToken.setData_PasswordChange(sUsername, sPasswordOld, sPasswordNew)
        iReturn = oToken.writeToken(_sFileToken, _sFilePublicKey, _sFileRandom)
        if iReturn:
            return iReturn

        # Done
        return 0


    def readToken(self, _sFileToken, _sFilePrivateKey, _bPasswordShow = False, _sEncoding = None):
        """
        Read token; returns a non-zero exit code in case of failure.
        """

        # Read and dump token data
        oToken = TokenReader()
        if _sEncoding:
            oToken.setEncoding(_sEncoding)
        iReturn = oToken.readToken(_sFileToken, _sFilePrivateKey)
        if iReturn:
            return iReturn
        dToken = oToken.getData()
        for sField in sorted(dToken.keys()):
            if not _bPasswordShow and sField in ('password-old', 'password-new'):
                continue
            sys.stdout.write('%s: %s\n' % (sField, dToken[ sField ]))

        # Done
        return 0


class TokenMain(Token):
    """
    Universal Password Changer Token Reader/Writer Main Executable
    """

    #------------------------------------------------------------------------------
    # CONSTRUCTORS / DESTRUCTOR
    #------------------------------------------------------------------------------

    def __init__(self):
        Token.__init__(self)

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
            metavar='<token-file>',
            default='-', nargs='?',
            help='Path to token file (default:[read]stdin/[write]stdout)')

        # ... read mode
        self.__oArgumentParser.add_argument(
            '-R', '--read', action='store_true',
            default=False,
            help='[Read] Read token (dump token content)')

        # ... (read) RSA private key file
        self.__oArgumentParser.add_argument(
            '-Rk', '--key_private', type=str,
            metavar='<key-file>',
            default='/etc/upwdchg/private.pem',
            help='[Read] Path to RSA private key file (PEM format; default:/etc/upwdchg/private.pem)')

        # ... (read) show password
        self.__oArgumentParser.add_argument(
            '-Rp', '--password_show', action='store_true',
            default=False,
            help='Show token passwords (not recommended)')

        # ... write mode
        self.__oArgumentParser.add_argument(
            '-W', '--write', action='store_true',
            default=False,
            help='[Write] Write (create) token')

        # ... (write) RSA public key file
        self.__oArgumentParser.add_argument(
            '-Wk', '--key_public', type=str,
            metavar='<key-file>',
            default='/etc/upwdchg/public.pem',
            help='[Write] Path to RSA public key file (PEM format; default:/etc/upwdchg/public.pem)')

        # ... (write) username
        self.__oArgumentParser.add_argument(
            '-Wu', '--username', type=str,
            metavar='<username>',
            help='[Write] User account name (automatically prompted for if unspecified)')

        # ... (write) password (new)
        self.__oArgumentParser.add_argument(
            '-Wp', '--password_new', type=str,
            metavar='<password-new>',
            help='[Write] New password (automatically prompted for if unspecified)')

        # ... (write) password (old)
        self.__oArgumentParser.add_argument(
            '-Wo', '--password_old', type=str,
            metavar='<password-old>',
            default='',
            help='[Write] Old password (default:empty/unspecified)')

        # ... (write) password (old) prompt
        self.__oArgumentParser.add_argument(
            '-WO', '--password_old_prompt', action='store_true',
            default=False,
            help='[Write] Prompt for old password')

        # ... (write) PRNG seed source
        self.__oArgumentParser.add_argument(
            '-Wr', '--random', type=str,
            metavar='<random-source>',
            default='/dev/urandom',
            help='[Write] Random number generator seed source (default:/dev/urandom)')

        # ... characters encoding
        self.__oArgumentParser.add_argument(
            '-E', '--encoding', type=str,
            metavar='<encoding>',
            default='utf-8',
            help='Input/output characters encoding (default:utf-8)')

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
            sys.stderr.write('ERROR[Token]: Failed to parse arguments; %s\n' % str(e))
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

        # Executes

        # ... write
        if self.__oArguments.write:
            iReturn = self.writeToken_PasswordChange(
                self.__oArguments.token,
                self.__oArguments.key_public,
                self.__oArguments.random,
                self.__oArguments.username,
                self.__oArguments.password_new,
                self.__oArguments.password_old,
                self.__oArguments.password_old_prompt,
                self.__oArguments.encoding,
                )
            if iReturn:
                return iReturn
            return 0

        # ... read
        if not self.__oArguments.write \
            or (self.__oArguments.read and self.__oArguments.token):
            iReturn = self.readToken(
                self.__oArguments.token,
                self.__oArguments.key_private,
                self.__oArguments.password_show,
                self.__oArguments.encoding,
                )
            if iReturn:
                return iReturn

        # Done
        return 0

