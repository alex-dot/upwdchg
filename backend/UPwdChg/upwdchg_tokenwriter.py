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
# ... deb: python-m2crypto
from UPwdChg import \
    TokenData, \
    UPWDCHG_DEFAULT_FILE_KEY_PRIVATE, \
    UPWDCHG_DEFAULT_FILE_KEY_PUBLIC, \
    UPWDCHG_DEFAULT_FILE_RANDOM, \
    UPWDCHG_CIPHER_ALGO, \
    UPWDCHG_CIPHER_KEY_LENGTH, \
    UPWDCHG_CIPHER_IV_LENGTH, \
    UPWDCHG_DIGEST_ALGO
import base64 as B64
import json as JSON
import M2Crypto as M2C
import os
import sys


#------------------------------------------------------------------------------
# CLASSES
#------------------------------------------------------------------------------

class TokenWriter(TokenData):
    """
    Universal Password Changer Token Writer
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
        _sFileRandom = UPWDCHG_DEFAULT_FILE_RANDOM,
        ):
        self._sFileKeyPrivate = _sFileKeyPrivate
        self._sFileKeyPublic = _sFileKeyPublic
        self._sFileRandom = _sFileRandom


    #------------------------------------------------------------------------------
    # METHODS
    #------------------------------------------------------------------------------

    #
    # Error handling
    #

    def __ERROR(self, _sMessage, _iError):
        self.error = _iError
        sys.stderr.write('ERROR[TokenWriter]: %s\n' % _sMessage)


    #
    # Data
    #

    def writeToken(self, _sFileToken):
        """
        Builds, encrypts and writes a UPwdChg token; returns a non-zero exit code in case of failure.
        """

        # Initialization
        self.error = 0

        # Compute the data digest
        try:
            oMessageDigest = M2C.EVP.MessageDigest(algo=UPWDCHG_DIGEST_ALGO)
            if oMessageDigest.update(self._getDigestData().encode('utf-8')) != 1:
                raise RuntimeError('failed to compute digest')
            sDataDigest = oMessageDigest.final()
        except Exception as e:
            self.__ERROR('Failed to compute data digest; %s' % str(e), 101)
            return self.error

        # Encode the data (JSON)
        try:
            dData_digest = self._dData
            dData_digest['digest'] = { \
                'algorithm': UPWDCHG_DIGEST_ALGO, \
                'base64': B64.b64encode(sDataDigest), \
            }
            sData = JSON.dumps(dData_digest, indent=4)
        except Exception as e:
            self.__ERROR('Failed to encode data; %s' % str(e), 111)
            return self.error

        # Encrypt the (symmetric) data key
        try:
            M2C.Rand.load_file(self._sFileRandom, UPWDCHG_CIPHER_KEY_LENGTH+UPWDCHG_CIPHER_IV_LENGTH)
            sDataKey = M2C.Rand.rand_bytes(UPWDCHG_CIPHER_KEY_LENGTH)
            if self._dData['type'] in ('password-nonce-request', 'password-change', 'password-reset'):
                sDataKeyCipherAlgo = 'public'
                # ... load the RSA public key
                oPublicKey = M2C.RSA.load_pub_key(self._sFileKeyPublic)
                # ... encrypt the data key
                sDataKeyEncrypted = oPublicKey.public_encrypt(sDataKey, M2C.RSA.pkcs1_oaep_padding)
            elif self._dData['type'] in ('password-nonce'):
                sDataKeyCipherAlgo = 'private'
                # ... load the RSA private key
                oPrivateKey = M2C.RSA.load_key(self._sFileKeyPrivate)
                # ... encrypt the data key
                sDataKeyEncrypted = oPrivateKey.private_encrypt(sDataKey, M2C.RSA.pkcs1_padding)
            else:
                raise RuntimeError('unexpected token/data type; %s' % self._dData['type'])
        except Exception as e:
            self.__ERROR('Failed to encrypt data key; %s' % str(e), 121)
            return self.error

        # Encrypt the data
        try:
            sDataIv = M2C.Rand.rand_bytes(UPWDCHG_CIPHER_IV_LENGTH);
            oDataCipher = M2C.EVP.Cipher(alg=UPWDCHG_CIPHER_ALGO, key=sDataKey, iv=sDataIv, op=M2C.encrypt)
            sDataEncrypted = oDataCipher.update(sData)
            sDataEncrypted += oDataCipher.final()
        except Exception as e:
            self.__ERROR('Failed to encrypt data; %s' % str(e), 131)
            return self.error

        # Encode the token (JSON)
        try:
            sToken = JSON.dumps( { \
                'type': 'application/x.upwdchg-token+json', \
                'data': { \
                    'cipher': { \
                        'algorithm': UPWDCHG_CIPHER_ALGO.replace('_', '-'), \
                        'iv': { \
                            'base64': B64.b64encode(sDataIv), \
                        }, \
                        'key': { \
                            'cipher': { \
                                'algorithm': sDataKeyCipherAlgo, \
                            }, \
                            'base64': B64.b64encode(sDataKeyEncrypted), \
                        }, \
                    }, \
                    'base64': B64.b64encode(sDataEncrypted), \
                }, \
            }, indent=4 )
        except Exception as e:
            self.__ERROR('Failed to encode token; %s' % str(e), 141)
            return self.error

        # Write the token to file
        try:
            if _sFileToken == '-':
                oFile = sys.stdout
            else:
                oFile = open(_sFileToken, 'w')
        except Exception as e:
            self.__ERROR('Failed to open token file; %s' % str(e), 151)
            return self.error
        try:
            oFile.write(sToken)
        except Exception as e:
            self.__ERROR('Failed to write token to file; %s' % str(e), 152)
        if oFile != sys.stdout:
            oFile.close()
        if self.error:
            return self.error

        # Done
        return 0
