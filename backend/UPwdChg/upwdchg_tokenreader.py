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
    UPWDCHG_ENCODING, \
    TokenData

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
                oFile = open(_sFileToken, 'r', encoding=UPWDCHG_ENCODING)
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
            byData = B64.b64decode(dToken['data']['base64'])
        except Exception as e:
            self.__ERROR('Failed to decode token data; %s' % str(e), 203)
            return self.error

        # Verify the data signature
        try:
            sDataSignatureAlgo = dToken['data']['signature']['algorithm'].lower()
            byDataSignature = B64.b64decode(dToken['data']['signature']['base64'].encode('ascii'))
            if sDataSignatureAlgo[:4] == 'rsa-':
                with open(self._sFileKeyPublic, 'r') as oFileKey:
                    # ... load the public key
                    mPublicKey = __import__('Cryptodome.PublicKey.RSA', fromlist=['Cryptodome.PublicKey'], level=0)
                    oPublicKey = mPublicKey.import_key(oFileKey.read())
                    # ... hash the data
                    mHash = __import__('Cryptodome.Hash.%s' % sDataSignatureAlgo[4:].upper(), fromlist=['Cryptodome.Hash'], level=0)
                    oHash = mHash.new(byData)
                    # ... verify the signature
                    PKCS1_SIGN.new(oPublicKey).verify(oHash, byDataSignature)
            else:
                raise RuntimeError('invalid/unsupported data signature algorithm; %s' % sDataSignatureAlgo)
        except Exception as e:
            self.__ERROR('Failed to verify data signature; %s' % str(e), 211)
            return self.error

        # Decrypt the (symmetric) data key
        try:
            byDataKey = B64.b64decode(dToken['data']['cipher']['key']['base64'])
            sDataKeyCipherAlgo = dToken['data']['cipher']['key']['cipher']['algorithm'].lower()
            if sDataKeyCipherAlgo == 'rsa':
                with open(self._sFileKeyPrivate, 'r') as oFileKey:
                    # ... load the private key
                    mPublicKey = __import__('Cryptodome.PublicKey.RSA', fromlist=['Cryptodome.PublicKey'], level=0)
                    oPrivateKey = mPublicKey.import_key(oFileKey.read())
                    # ... decrypt the data key
                    oCipher = PKCS1_OAEP.new(oPrivateKey)
                    byDataKey = oCipher.decrypt(byDataKey)
            else:
                raise RuntimeError('invalid/unsupported data key cipher; %s' % sDataKeyCipherAlgo)
        except Exception as e:
            self.__ERROR('Failed to decrypt data key; %s' % str(e), 212)
            return self.error

        # Decrypt the data
        try:
            sDataCipherAlgo = dToken['data']['cipher']['algorithm'].lower().replace('-', '_')
            try:
                byDataIv = B64.b64decode(dToken['data']['cipher']['iv']['base64'])
            except Exception as e:
                byDataIv = b''
            if sDataCipherAlgo in ('aes_256_cbc', 'aes_192_cbc', 'aes_128_cbc'):
                mCipher = __import__('Cryptodome.Cipher.AES', fromlist=['Cryptodome.Cipher'], level=0)
                oCipher = mCipher.new(byDataKey, mCipher.MODE_CBC, iv=byDataIv)
                sData = PADDING.unpad(oCipher.decrypt(byData), mCipher.block_size, 'pkcs7').decode('utf-8')
            elif sDataCipherAlgo in ('bf_cbc'):
                mCipher = __import__('Cryptodome.Cipher.Blowfish', fromlist=['Cryptodome.Cipher'], level=0)
                oCipher = mCipher.new(byDataKey, mCipher.MODE_CBC, iv=byDataIv)
                sData = PADDING.unpad(oCipher.decrypt(byData), mCipher.block_size, 'pkcs7').decode('utf-8')
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
            byDataDigest_given = B64.b64decode(dData['digest']['base64'].encode('ascii'))
            dData.pop('digest')
            if sDataDigestAlgo in ('sha512', 'sha384', 'sha256', 'sha224', 'sha1', 'md5'):
                mHash = __import__('Cryptodome.Hash.%s' % sDataDigestAlgo.upper(), fromlist=['Cryptodome.Hash'], level=0)
                oHash = mHash.new(self._getDigestData(dData).encode('utf-8'))
                byDataDigest_compute = oHash.digest()
            else:
                raise RuntimeError('invalid/unsupported data digest; %s' % sDataDigestAlgo)
        except Exception as e:
            self.__ERROR('Failed to compute data digest; %s' % str(e), 241)
            return self.error
        if byDataDigest_compute != byDataDigest_given:
            self.__ERROR('Invalid data digest', 242)
            return self.error

        # Save data
        self._sData = sData
        self._dData = dData
        return 0
