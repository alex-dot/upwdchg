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
    UPWDCHG_DEFAULT_FILE_KEY_PRIVATE, \
    UPWDCHG_DEFAULT_FILE_KEY_PUBLIC, \
    UPWDCHG_CIPHER_ALGO, \
    UPWDCHG_CIPHER_KEY_LENGTH, \
    UPWDCHG_CIPHER_IV_LENGTH, \
    UPWDCHG_DIGEST_ALGO
import base64 as B64
import json as JSON
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
        self.config()

    def config(self,
        _sFileKeyPrivate = UPWDCHG_DEFAULT_FILE_KEY_PRIVATE,
        _sFileKeyPublic = UPWDCHG_DEFAULT_FILE_KEY_PUBLIC,
        ):
        self._sFileKeyPrivate = _sFileKeyPrivate
        self._sFileKeyPublic = _sFileKeyPublic


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

    def readToken(self, _sFileToken):
        """
        Reads, decrypts and parse a UPwdChg token; returns a non-zero exit code in case of failure.
        """

        # Initialization
        self.error = 0

        # Load the token from file
        # ... open the file
        try:
            if _sFileToken == '-':
                oFile = sys.stdin
            else:
                oFile = open(_sFileToken, 'r')
        except Exception as e:
           self.__ERROR('Failed to open token file; %s' % str(e), 201)
           return self.error
        # ... decode the token (JSON)
        try:
            dToken = JSON.load(oFile)
            if not 'type' in dToken:
                raise RuntimeError('invalid token')
            if dToken['type'] != 'application/x.upwdchg-token+json':
                raise RuntimeError('invalid token type; %s' % dToken['type'])
        except Exception as e:
            self.__ERROR('Failed to decode token; %s' % str(e), 202)
        # ... close the file
        if oFile != sys.stdin:
            oFile.close()
        if self.error:
            return self.error

        # Decode the data (Base64)
        try:
            sData = B64.b64decode(dToken['data']['base64'])
        except Exception as e:
            self.__ERROR('Failed to decode token data; %s' % str(e), 203)
            return self.error

        # Decrypt the (symmetric) data key
        try:
            sDataKey = B64.b64decode(dToken['data']['cipher']['key']['base64'])
            sDataKeyCipherAlgo = dToken['data']['cipher']['key']['cipher']['algorithm'].lower()
            if sDataKeyCipherAlgo == 'public':
                # ... load the RSA private key
                oPrivateKey = M2C.RSA.load_key(self._sFileKeyPrivate)
                # ... decrypt the data key
                sDataKey = oPrivateKey.private_decrypt(sDataKey, M2C.RSA.pkcs1_oaep_padding)
            elif sDataKeyCipherAlgo == 'private':
                # ... load the RSA public key
                oPublicKey = M2C.RSA.load_pub_key(self._sFileKeyPublic)
                # ... decrypt the data key
                sDataKey = oPublicKey.public_decrypt(sDataKey, M2C.RSA.pkcs1_padding)
            else:
                raise RuntimeError('invalid/unsupported data key cipher; %s' % sDataKeyCipherAlgo)
        except Exception as e:
            self.__ERROR('Failed to decrypt data key; %s' % str(e), 211)
            return self.error

        # Decrypt the data
        try:
            sDataCipherAlgo = dToken['data']['cipher']['algorithm'].lower().replace('-', '_')
            try:
                sDataIv = B64.b64decode(dToken['data']['cipher']['iv']['base64'])
            except Exception as e:
                sDataIv = ''
            if sDataCipherAlgo in ('aes_256_cbc', 'aes_192_cbc', 'aes_128_cbc', 'bf_cbc'):
                oCipher = M2C.EVP.Cipher(alg=sDataCipherAlgo, key=sDataKey, iv=sDataIv, op=M2C.decrypt)
                sData = oCipher.update(sData)
                sData += oCipher.final()
            else:
                raise RuntimeError('invalid/unsupported data cipher; %s' % sDataCipherAlgo)
        except Exception as e:
            self.__ERROR('Failed to decrypt data; %s' % str(e), 221)
            return self.error

        # Decode the data (JSON)
        try:
            dData = JSON.loads(sData)
            if not 'type' in dData:
                raise RuntimeError('invalid data')
            if not dData['type'] in ('password-nonce-request', 'password-nonce', 'password-change', 'password-reset'):
                raise RuntimeError('invalid data type; %s' % dData['type'])
        except Exception as e:
            self.__ERROR('Failed to decode data; %s' % str(e), 231)
            return self.error

        # Check the data digest
        try:
            sDataDigestAlgo = dData['digest']['algorithm'].lower()
            sDataDigest_given = B64.b64decode(dData['digest']['base64'])
            dData.pop('digest')
            if sDataDigestAlgo in ('sha512', 'sha384', 'sha256', 'sha224', 'sha1', 'md5'):
                oMessageDigest = M2C.EVP.MessageDigest(algo=sDataDigestAlgo)
                if oMessageDigest.update(self._getDigestData(dData).encode('utf-8')) != 1:
                    raise RuntimeError('failed to compute digest')
                sDataDigest_compute = oMessageDigest.final()
            else:
                raise RuntimeError('invalid/unsupported data digest; %s' % sDataDigestAlgo)
        except Exception as e:
            self.__ERROR('Failed to compute data digest; %s' % str(e), 241)
            return self.error
        if sDataDigest_compute != sDataDigest_given:
            self.__ERROR('Invalid data digest', 242)
            return self.error

        # Save data
        self._sData = sData
        self._dData = dData
        return 0
