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
    UPWDCHG_VERSION, \
    TokenReader, \
    TokenWriter

# Standard
import argparse as AP
import getpass
import json as JSON
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
        # Fields
        self._bDebug = False
        self._sFileKeyPrivate = None
        self._sFileKeyPublic = None
        self._iPasswordNonceTtl = 300

    def config(self, _sFileKeyPrivate, _sFileKeyPublic, _iPasswordNonceTtl = 300):
        self._sFileKeyPrivate = _sFileKeyPrivate
        self._sFileKeyPublic = _sFileKeyPublic
        self._iPasswordNonceTtl = _iPasswordNonceTtl


    #------------------------------------------------------------------------------
    # METHODS
    #------------------------------------------------------------------------------

    def writeToken_PasswordNonceRequest(self,
        _sFileToken,
        _sUsername = None
        ):
        """
        Write a 'password-nonce-request' token; returns a non-zero exit code in case of failure.
        """

        # Token data

        # ... username
        sUsername = _sUsername
        while not sUsername:
            sUsername = input('Username: ')

        # Write token
        oToken = TokenWriter()
        oToken.config(self._sFileKeyPrivate, self._sFileKeyPublic)
        oToken.setData_PasswordNonceRequest(sUsername)
        iReturn = oToken.writeToken(_sFileToken)
        return iReturn


    def writeToken_PasswordNonce(self,
        _sFileToken,
        _sUsername = None,
        _sPasswordNonce = None, _bPasswordNoncePrompt = False
        ):
        """
        Write a 'password-nonce' token; returns a non-zero exit code in case of failure.
        """

        # Token data

        # ... username
        sUsername = _sUsername
        while not sUsername:
            sUsername = input('Username: ')

        # ... password (nonce)
        sPasswordNonce = _sPasswordNonce
        while _bPasswordNoncePrompt and not sPasswordNonce:
            sPasswordNonce_confirm = None
            while sPasswordNonce_confirm is None or sPasswordNonce != sPasswordNonce_confirm:
                if sPasswordNonce_confirm is not None:
                    sys.stderr.write('Password mismatch! Please try again...\n')
                sPasswordNonce = getpass.getpass('Password nonce: ')
                sPasswordNonce_confirm = getpass.getpass('Password nonce (confirm): ')
        try:
            (sPasswordNonce_id, sPasswordNonce_secret) = sPasswordNonce.split('-', 1)
        except Exception as e:
            sys.stderr.write('ERROR[Token]: Invalid password nonce!\n')
            return 1

        # Write token
        oToken = TokenWriter()
        oToken.config(self._sFileKeyPrivate, self._sFileKeyPublic)
        oToken.setData_PasswordNonce(sUsername, sPasswordNonce, self._iPasswordNonceTtl)
        iReturn = oToken.writeToken(_sFileToken)
        if iReturn:
            return iReturn

        # Done
        return 0


    def writeToken_PasswordChange(self,
        _sFileToken,
        _sUsername = None,
        _sPasswordNew = None,
        _sPasswordOld = None, _bPasswordOldPrompt = False,
        _sPasswordNonce = None, _bPasswordNoncePrompt = False
        ):
        """
        Write a 'password-change' token; returns a non-zero exit code in case of failure.
        """

        # Token data

        # ... username
        sUsername = _sUsername
        while not sUsername:
            sUsername = input('Username: ')

        # ... password (nonce)
        sPasswordNonce = _sPasswordNonce
        while _bPasswordNoncePrompt and not sPasswordNonce:
            sPasswordNonce_confirm = None
            while sPasswordNonce_confirm is None or sPasswordNonce != sPasswordNonce_confirm:
                if sPasswordNonce_confirm is not None:
                    sys.stderr.write('Password mismatch! Please try again...\n')
                sPasswordNonce = getpass.getpass('Password nonce: ')
                sPasswordNonce_confirm = getpass.getpass('Password nonce (confirm): ')
        if sPasswordNonce:
            try:
                (sPasswordNonce_id, sPasswordNonce_secret) = sPasswordNonce.split('-', 1)
            except Exception as e:
                sys.stderr.write('ERROR[Token]: Invalid password nonce!\n')
                return 1

        # ... password (old)
        sPasswordOld = _sPasswordOld
        while _bPasswordOldPrompt and not sPasswordOld:
            sPasswordOld_confirm = None
            while sPasswordOld_confirm is None or sPasswordOld != sPasswordOld_confirm:
                if sPasswordOld_confirm is not None:
                    sys.stderr.write('Password mismatch! Please try again...\n')
                sPasswordOld = getpass.getpass('Old Password: ')
                sPasswordOld_confirm = getpass.getpass('Old Password (confirm): ')

        # ... password (new)
        sPasswordNew = _sPasswordNew
        while not sPasswordNew:
            sPasswordNew_confirm = None
            while sPasswordNew_confirm is None or sPasswordNew != sPasswordNew_confirm:
                if sPasswordNew_confirm is not None:
                    sys.stderr.write('Password mismatch! Please try again...\n')
                sPasswordNew = getpass.getpass('New Password: ')
                sPasswordNew_confirm = getpass.getpass('New Password (confirm): ')

        # Write token
        oToken = TokenWriter()
        oToken.config(self._sFileKeyPrivate, self._sFileKeyPublic)
        oToken.setData_PasswordChange(sUsername, sPasswordNew, sPasswordOld, sPasswordNonce)
        iReturn = oToken.writeToken(_sFileToken)
        if iReturn:
            return iReturn

        # Done
        return 0


    def writeToken_PasswordReset(self,
        _sFileToken,
        _sUsername = None, _sPasswordNew = None, _sPasswordNonce = None, _bPasswordNoncePrompt = False
        ):
        """
        Write a 'password-reset' token; returns a non-zero exit code in case of failure.
        """

        # Token data

        # ... username
        sUsername = _sUsername
        while not sUsername:
            sUsername = input('Username: ')

        # ... password (nonce)
        sPasswordNonce = _sPasswordNonce
        while _bPasswordNoncePrompt and not sPasswordNonce:
            sPasswordNonce_confirm = None
            while sPasswordNonce_confirm is None or sPasswordNonce != sPasswordNonce_confirm:
                if sPasswordNonce_confirm is not None:
                    sys.stderr.write('Password mismatch! Please try again...\n')
                sPasswordNonce = getpass.getpass('Password nonce: ')
                sPasswordNonce_confirm = getpass.getpass('Password nonce (confirm): ')
        try:
            (sPasswordNonce_id, sPasswordNonce_secret) = sPasswordNonce.split('-', 1)
        except Exception as e:
            sys.stderr.write('ERROR[Token]: Invalid password nonce!\n')
            return 1

        # ... password (new)
        sPasswordNew = _sPasswordNew
        while not sPasswordNew:
            sPasswordNew_confirm = None
            while sPasswordNew_confirm is None or sPasswordNew != sPasswordNew_confirm:
                if sPasswordNew_confirm is not None:
                    sys.stderr.write('Password mismatch! Please try again...\n')
                sPasswordNew = getpass.getpass('New Password: ')
                sPasswordNew_confirm = getpass.getpass('New Password (confirm): ')

        # Write token
        oToken = TokenWriter()
        oToken.config(self._sFileKeyPrivate, self._sFileKeyPublic)
        oToken.setData_PasswordReset(sUsername, sPasswordNew, sPasswordNonce)
        iReturn = oToken.writeToken(_sFileToken)
        if iReturn:
            return iReturn

        # Done
        return 0


    def readToken(self,
        _sFileToken,
        _bPasswordShow = False
        ):
        """
        Read token; returns a non-zero exit code in case of failure.
        """

        # Read and dump token data
        oToken = TokenReader()
        oToken.config(self._sFileKeyPrivate, self._sFileKeyPublic)
        iReturn = oToken.readToken(_sFileToken)
        if iReturn:
            return iReturn
        dToken = oToken.getData()
        for sField in list(dToken.keys()):
            if not _bPasswordShow and sField[0:8]=='password':
                dToken.pop(sField)
        sys.stdout.write('%s\n' % JSON.dumps(dToken, indent=4, sort_keys=True))

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
            metavar='<file>',
            default='-', nargs='?',
            help='Path to token file (default:[read]stdin/[write]stdout)')

        # ... read mode
        self.__oArgumentParser.add_argument(
            '-R', '--read', action='store_true',
            default=False,
            help='[Read] Read token (dump token content)')

        # ... (read) show password
        self.__oArgumentParser.add_argument(
            '-Rp', '--password_show', action='store_true',
            default=False,
            help='[Read] Show token passwords (not recommended)')

        # ... write mode
        self.__oArgumentParser.add_argument(
            '-W', '--write', action='store_true',
            default=False,
            help='[Write] Write (create) token')

        # ... (write) type
        self.__oArgumentParser.add_argument(
            '-Wt', '--type', type=str,
            metavar='<string>',
            default='password-change',
            help='[Write] Token type (default:password-change)')

        # ... (write) username
        self.__oArgumentParser.add_argument(
            '-Wu', '--username', type=str,
            metavar='<string>',
            help='[Write] User account name (automatically prompted for if unspecified)')

        # ... (write) password (new)
        self.__oArgumentParser.add_argument(
            '-Wp', '--password_new', type=str,
            metavar='<string>',
            help='[Write] New password (automatically prompted for if unspecified)')

        # ... (write) password (old)
        self.__oArgumentParser.add_argument(
            '-Wo', '--password_old', type=str,
            metavar='<string>',
            default='',
            help='[Write] Old password (default:empty/unspecified)')

        # ... (write) password (old) prompt
        self.__oArgumentParser.add_argument(
            '-WO', '--password_old_prompt', action='store_true',
            default=False,
            help='[Write] Prompt for old password')

        # ... (write) password (nonce)
        self.__oArgumentParser.add_argument(
            '-Wn', '--password_nonce', type=str,
            metavar='<string>',
            default='',
            help='[Write] Nonce password (default:empty/unspecified)')

        # ... (write) password (nonce) prompt
        self.__oArgumentParser.add_argument(
            '-WN', '--password_nonce_prompt', action='store_true',
            default=False,
            help='[Write] Prompt for password nonce')

        # ... private key file
        self.__oArgumentParser.add_argument(
            '-Kv', '--key_private', type=str,
            metavar='<file>',
            default='/etc/upwdchg/frontend/private.pem',
            help='Path to the private key file (PEM format; default:/etc/upwdchg/frontend/private.pem)')

        # ... public key file
        self.__oArgumentParser.add_argument(
            '-Ku', '--key_public', type=str,
            metavar='<file>',
            default='/etc/upwdchg/backend/public.pem',
            help='Path to the public key file (PEM format; default:/etc/upwdchg/backend/public.pem)')

        # ... password nonce TTL
        self.__oArgumentParser.add_argument(
            '-Nt', '--password_nonce_ttl', type=int,
            metavar='<integer>',
            default=300,
            help='Password nonce Time-to-Live, in seconds (default:300)')

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
        except Exception as e:
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

        # Configure token
        self.config(
            self.__oArguments.key_private,
            self.__oArguments.key_public,
            self.__oArguments.password_nonce_ttl,
            )

        # Executes

        # ... write
        if self.__oArguments.write:
            if self.__oArguments.type == 'password-nonce-request':
                iReturn = self.writeToken_PasswordNonceRequest(
                    self.__oArguments.token,
                    self.__oArguments.username,
                    )
            elif self.__oArguments.type == 'password-nonce':
                iReturn = self.writeToken_PasswordNonce(
                    self.__oArguments.token,
                    self.__oArguments.username,
                    self.__oArguments.password_nonce,
                    self.__oArguments.password_nonce_prompt,
                    )
            elif self.__oArguments.type == 'password-change':
                iReturn = self.writeToken_PasswordChange(
                    self.__oArguments.token,
                    self.__oArguments.username,
                    self.__oArguments.password_new,
                    self.__oArguments.password_old,
                    self.__oArguments.password_old_prompt,
                    self.__oArguments.password_nonce,
                    self.__oArguments.password_nonce_prompt,
                    )
            elif self.__oArguments.type == 'password-reset':
                iReturn = self.writeToken_PasswordReset(
                    self.__oArguments.token,
                    self.__oArguments.username,
                    self.__oArguments.password_new,
                    self.__oArguments.password_nonce,
                    self.__oArguments.password_nonce_prompt,
                    )
            else:
                sys.stderr.write('ERROR[Token]: Invalid token type; %s\n' % self.__oArguments.type)
                iReturn = 1
            if iReturn:
                return iReturn
            return 0

        # ... read
        if not self.__oArguments.write \
            or (self.__oArguments.read and self.__oArguments.token):
            iReturn = self.readToken(
                self.__oArguments.token,
                self.__oArguments.password_show
            )
            if iReturn:
                return iReturn

        # Done
        return 0
