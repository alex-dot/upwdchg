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
# ... deb: python-m2crypto
from UPwdChg import \
    TokenData, \
    UPWDCHG_CIPHER_ALGO, \
    UPWDCHG_CIPHER_KEY_LENGTH, \
    UPWDCHG_CIPHER_IV_LENGTH, \
    UPWDCHG_DIGEST_ALGO
import base64 as B64
import M2Crypto as M2C
import sys


#------------------------------------------------------------------------------
# CLASSES
#------------------------------------------------------------------------------

class TokenReader(TokenData):
    """
    Universal Password Changer Token Reader
    """

    #------------------------------------------------------------------------------
    # CONSTRUCTORS / DESTRUCTOR
    #------------------------------------------------------------------------------

    def __init__(self):
        TokenData.__init__(self)

        # Fields
        self.error = 0


    #------------------------------------------------------------------------------
    # METHODS
    #------------------------------------------------------------------------------

    #
    # Error handling
    #

    def __ERROR(self, _sMessage, _iError):
        self.error = _iError
        sys.stderr.write('ERROR[TokenReader]: %s\n' % _sMessage)


    #
    # Data
    #

    def read(self, _sFileToken, _sFilePrivateKey):
        """
        Reads, decrypts and parse a UPwdChg token; returns a non-zero exit code in case of failure.
        """

        # Initialization
        self.error = 0

        # Read the token content
        try:
            if _sFileToken == '-':
                oFile = sys.stdin
            else:
                oFile = open(_sFileToken, 'r')
        except Exception as e:
           self.__ERROR('Failed to open token file; %s' % str(e), 2001)
           return self.error
        try:
            iLine = 0
            for sLine in oFile:
                iLine += 1
                if iLine == 1:
                    if sLine.strip('\n') != '# UNIVERSAL PASSWORD CHANGER TOKEN, V1.0':
                        raise Exception('invalid magic/version string')
                elif iLine == 2:
                    sCipherKeyIvEncrypted = B64.b64decode(sLine)
                elif iLine == 3:
                    sDataEncrypted = B64.b64decode(sLine)
                else:
                    # This should not happen... but oh well!
                    break
            if iLine < 3:
                raise Exception('incomplete data')
        except Exception as e:
            self.__ERROR('Invalid token; %s' % str(e), 2002)
        if oFile != sys.stdin:
            oFile.close()
        if self.error:
            return self.error


        # Load the RSA private key
        try:
            oPrivateKey = M2C.RSA.load_key(_sFilePrivateKey)
        except Exception as e:
            self.__ERROR('Failed to load RSA private key; %s' % str(e), 2021)
            return self.error

        # Decrypt the (symmetric) data key and initialization vector
        try:
            sCipherKeyIv = oPrivateKey.private_decrypt(sCipherKeyIvEncrypted, M2C.RSA.pkcs1_oaep_padding)
        except Exception as e:
            self.__ERROR('Failed to decrypt data key/IV; %s' % str(e), 2031)
            return self.error

        # Decrypt the data
        sCipherKey = sCipherKeyIv[:UPWDCHG_CIPHER_KEY_LENGTH]
        sCipherIv = sCipherKeyIv[-UPWDCHG_CIPHER_IV_LENGTH:]
        try:
            oCipher = M2C.EVP.Cipher(alg=UPWDCHG_CIPHER_ALGO, key=sCipherKey, iv=sCipherIv, op=M2C.decrypt)
        except Exception as e:
            self.__ERROR('Failed to initialize data decryption; %s' % str(e), 2041)
            return self.error
        try:
            sData = oCipher.update(sDataEncrypted)
            sData += oCipher.final()
        except Exception as e:
            self.__ERROR('Failed to decrypt data; %s' % str(e), 2042)
            return self.error

        # Check data
        lData = sData.split('\n', 1)
        if len(lData) < 2:
            self.__ERROR('Invalid data', 2051)
            return self.error
        (sDigest_1, sData) = lData
        try:
            oMessageDigest = M2C.EVP.MessageDigest(algo=UPWDCHG_DIGEST_ALGO)
        except Exception as e:
            self.__ERROR('Failed to initialize data digest; %s' % str(e), 2052)
            return self.error
        if oMessageDigest.update(sData) != 1:
            self.__ERROR('Failed to compute data digest', 2053)
            return self.error
        sDigest_2 = oMessageDigest.final()
        if sDigest_2 != B64.b64decode(sDigest_1):
            self.__ERROR('Corrupted data', 2054)
            return self.error
        lData = sData.split('\n')
        if len(lData) != 4:
            self.__ERROR('Invalid data', 2055)
            return self.error

        # Save data
        (self._uTimestamp, self._uUsername, self._uPasswordOld, self._uPasswordNew) = map(lambda _s:_s.decode('utf-8'), lData)
        return 0
