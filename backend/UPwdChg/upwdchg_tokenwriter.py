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
    TokenData, \
    UPWDCHG_ENCODING, \
    UPWDCHG_PUBLIC_ALGO, \
    UPWDCHG_CIPHER_ALGO, \
    UPWDCHG_CIPHER_KEY_LENGTH, \
    UPWDCHG_CIPHER_IV_LENGTH, \
    UPWDCHG_DIGEST_ALGO

# Extra
# ... deb: python3-pycryptodome
import Cryptodome.Cipher as CIPHER
from Cryptodome.Cipher import \
    PKCS1_OAEP
import Cryptodome.Hash as HASH
import Cryptodome.PublicKey as PUBKEY
import Cryptodome.Random as RANDOM
from Cryptodome.Signature import \
    pkcs1_15 as PKCS1_SIGN
import Cryptodome.Util.Padding as PADDING

# Standard
import base64 as B64
import json as JSON
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
        self._sFileKeyPrivate = None
        self._sFileKeyPublic = None

    def config(self, _sFileKeyPrivate, _sFileKeyPublic):
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
            mHash = __import__('Cryptodome.Hash.%s' % UPWDCHG_DIGEST_ALGO.upper(), fromlist=['Cryptodome.Hash'], level=0)
            oHash = mHash.new(self._getDigestData().encode('utf-8'))
            byDataDigest = oHash.digest()
        except Exception as e:
            self.__ERROR('Failed to compute data digest; %s' % str(e), 101)
            return self.error

        # Encode the data (JSON)
        try:
            dData_digest = self._dData
            dData_digest['digest'] = { \
                'algorithm': UPWDCHG_DIGEST_ALGO, \
                'base64': B64.b64encode(byDataDigest).decode('ascii'), \
            }
            sData = JSON.dumps(dData_digest, indent=4)
        except Exception as e:
            self.__ERROR('Failed to encode data; %s' % str(e), 111)
            return self.error

        # Encrypt the (symmetric) data key
        try:
            byDataKey = RANDOM.get_random_bytes(UPWDCHG_CIPHER_KEY_LENGTH)
            if UPWDCHG_PUBLIC_ALGO in ('rsa'):
                with open(self._sFileKeyPublic, 'r') as oFileKey:
                    # ... load the public key
                    mPublicKey = __import__('Cryptodome.PublicKey.RSA', fromlist=['Cryptodome.PublicKey'], level=0)
                    oPublicKey = mPublicKey.import_key(oFileKey.read())
                    # ... encrypt the data key
                    oCipher = PKCS1_OAEP.new(oPublicKey)
                    byDataKeyEncrypted = oCipher.encrypt(byDataKey)
            else:
                raise RuntimeError('invalid/unsupported data key cipher; %s' % UPWDCHG_PUBLIC_ALGO)
        except Exception as e:
            self.__ERROR('Failed to encrypt data key; %s' % str(e), 121)
            return self.error

        # Encrypt the data
        try:
            byDataIv = RANDOM.get_random_bytes(UPWDCHG_CIPHER_IV_LENGTH)
            if UPWDCHG_CIPHER_ALGO in ('aes_256_cbc', 'aes_192_cbc', 'aes_128_cbc'):
                mCipher = __import__('Cryptodome.Cipher.AES', fromlist=['Cryptodome.Cipher'], level=0)
                oCipher = mCipher.new(byDataKey, mCipher.MODE_CBC, iv=byDataIv)
                byDataEncrypted = oCipher.encrypt(PADDING.pad(sData.encode('utf-8'), mCipher.block_size, 'pkcs7'))
            elif UPWDCHG_CIPHER_ALGO in ('bf_cbc'):
                mCipher = __import__('Cryptodome.Cipher.Blowfish', fromlist=['Cryptodome.Cipher'], level=0)
                oCipher = mCipher.new(byDataKey, mCipher.MODE_CBC, iv=byDataIv)
                byDataEncrypted = oCipher.encrypt(PADDING.pad(sData.encode('utf-8'), mCipher.block_size, 'pkcs7'))
            else:
                raise RuntimeError('invalid/unsupported data cipher; %s' % UPWDCHG_CIPHER_ALGO)
        except Exception as e:
            self.__ERROR('Failed to encrypt data; %s' % str(e), 131)
            return self.error

        # Sign the data
        try:
            if UPWDCHG_PUBLIC_ALGO in ('rsa'):
                with open(self._sFileKeyPrivate, 'r') as oFileKey:
                    # ... load the public key
                    mPublicKey = __import__('Cryptodome.PublicKey.RSA', fromlist=['Cryptodome.PublicKey'], level=0)
                    oPrivateKey = mPublicKey.import_key(oFileKey.read())
                    # ... hash the data
                    mHash = __import__('Cryptodome.Hash.%s' % UPWDCHG_DIGEST_ALGO.upper(), fromlist=['Cryptodome.Hash'], level=0)
                    oHash = mHash.new(byDataEncrypted)
                    # ... sign the data
                    byDataSignature = PKCS1_SIGN.new(oPrivateKey).sign(oHash)
            else:
                raise RuntimeError('invalid/unsupported data signature algorithm; %s' % UPWDCHG_PUBLIC_ALGO)
        except Exception as e:
            self.__ERROR('Failed to sign data; %s' % str(e), 132)
            return self.error

        # Encode the token (JSON)
        try:
            sToken = JSON.dumps( { \
                'type': 'application/x.upwdchg-token+json', \
                'data': { \
                    'cipher': { \
                        'algorithm': UPWDCHG_CIPHER_ALGO.replace('_', '-'), \
                        'iv': { \
                            'base64': B64.b64encode(byDataIv).decode('ascii'), \
                        }, \
                        'key': { \
                            'cipher': { \
                                'algorithm': UPWDCHG_PUBLIC_ALGO, \
                            }, \
                            'base64': B64.b64encode(byDataKeyEncrypted).decode('ascii'), \
                        }, \
                    }, \
                    'signature': { \
                        'algorithm': '%s-%s' % (UPWDCHG_PUBLIC_ALGO, UPWDCHG_DIGEST_ALGO), \
                        'base64': B64.b64encode(byDataSignature).decode('ascii'), \
                    }, \
                    'base64': B64.b64encode(byDataEncrypted).decode('ascii'), \
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
                oFile = open(_sFileToken, 'w', encoding=UPWDCHG_ENCODING)
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
