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
    UPWDCHG_PWHASH_METHOD, \
    UPWDCHG_PWHASH_ALGO, \
    UPWDCHG_PWHASH_ITERATIONS, \
    UPWDCHG_IDHASH_METHOD, \
    UPWDCHG_IDHASH_ALGO

# Extra
# ... deb: python3-pycryptodome
import Cryptodome.Hash as HASH
from Cryptodome.Hash import HMAC
from Cryptodome.Protocol.KDF import PBKDF2
import Cryptodome.Random as RANDOM

# Standard
import base64 as B64
from calendar import \
    timegm
import json as JSON
from sys import \
    modules
from time import \
    gmtime, \
    strftime, \
    strptime


#------------------------------------------------------------------------------
# CLASSES
#------------------------------------------------------------------------------

class TokenData:
    """
    Universal Password Changer Token Data
    """

    #------------------------------------------------------------------------------
    # CONSTRUCTORS / DESTRUCTOR
    #------------------------------------------------------------------------------

    def __init__(self):
        # Fields
        self._dData = None
        self._sData = None


    #------------------------------------------------------------------------------
    # METHODS
    #------------------------------------------------------------------------------

    #
    # Helpers
    #

    def makePasswordNonce(self, _liPasswordNonceLength, _bSplit=False):
        """
        Make a password nonce of the given (components) length.
        Returns its ID and secret components split if specified.
        """
        try:
            iPasswordNonceLength_id = _liPasswordNonceLength[0]
            iPasswordNonceLength_secret = _liPasswordNonceLength[1]
        except TypeError:
            iPasswordNonceLength_id = iPasswordNonceLength_secret = _liPasswordNonceLength
        iPasswordNonceLength_total = iPasswordNonceLength_id+iPasswordNonceLength_secret
        sPasswordNonce = B64.b64encode(RANDOM.get_random_bytes(2*iPasswordNonceLength_total), b'**').decode('ascii').rstrip('=').replace('*', '')
        sPasswordNonce_id = sPasswordNonce[0:iPasswordNonceLength_id]
        sPasswordNonce_secret = sPasswordNonce[iPasswordNonceLength_id:iPasswordNonceLength_total]
        if _bSplit:
            return [sPasswordNonce_id, sPasswordNonce_secret]
        return sPasswordNonce_id+'-'+sPasswordNonce_secret


    def splitPasswordNonce(self, _sPasswordNonce):
        """
        Splits the password nonce into its ID and secret components
        """

        return _sPasswordNonce.split('-', 1)


    #
    # Setters
    #

    def setData_PasswordNonceRequest(self, _sUsername, _sSessionId=None):
        """
        Sets the "password-nonce-request" token data
        """

        self._dData = { \
            'type': 'password-nonce-request', \
            'timestamp': strftime('%Y-%m-%dT%H:%M:%SZ', gmtime()), \
            'username': _sUsername, \
        }
        if _sSessionId:
            self._dData['session-id'] = _sSessionId
        self._sData = None


    def setData_PasswordNonce(self, _sUsername, _sPasswordNonce, _iPasswordNonceTtl, _sSessionId=None):
        """
        Sets the "password-nonce" token data
        """

        # Split password nonce
        (sPasswordNonce_id, sPasswordNonce_secret) = self.splitPasswordNonce(_sPasswordNonce)

        # Secret (hashed!)
        if UPWDCHG_PWHASH_METHOD == 'pbkdf2':
            mHash = __import__('Cryptodome.Hash.%s' % UPWDCHG_PWHASH_ALGO.upper(), fromlist=['Cryptodome.Hash'], level=0)
            byHashAlgo_salt = RANDOM.get_random_bytes(mHash.block_size)
            byHash_compute = PBKDF2(
                sPasswordNonce_secret.encode(UPWDCHG_ENCODING), byHashAlgo_salt,
                mHash.digest_size, UPWDCHG_PWHASH_ITERATIONS,
                lambda p, s: HMAC.new(p, s, mHash).digest()
            )
            dPasswordNonce_secret = { \
                'base64': B64.b64encode(byHash_compute).decode('ascii'), \
                'hash': { \
                    'algorithm': "%s-%s" % (UPWDCHG_PWHASH_METHOD, UPWDCHG_PWHASH_ALGO), \
                    'salt': { \
                        'base64': B64.b64encode(byHashAlgo_salt).decode('ascii'), \
                    }, \
                    'iterations': UPWDCHG_PWHASH_ITERATIONS, \
                }, \
            }
        elif UPWDCHG_PWHASH_METHOD == 'hmac':
            mHash = __import__('Cryptodome.Hash.%s' % UPWDCHG_PWHASH_ALGO.upper(), fromlist=['Cryptodome.Hash'], level=0)
            byHashAlgo_salt = RANDOM.get_random_bytes(mHash.block_size)
            oHmac = HMAC.new(byHashAlgo_salt, sPasswordNonce_secret.encode(UPWDCHG_ENCODING), mHash)
            byHash_compute = oHmac.digest()
            dPasswordNonce_secret = { \
                'base64': B64.b64encode(byHash_compute).decode('ascii'), \
                'hash': { \
                    'algorithm': "%s-%s" % (UPWDCHG_PWHASH_METHOD, UPWDCHG_PWHASH_ALGO), \
                    'salt': { \
                        'base64': B64.b64encode(byHashAlgo_salt).decode('ascii'), \
                    }, \
                }, \
            }
        elif UPWDCHG_PWHASH_METHOD == 'hash':
            mHash = __import__('Cryptodome.Hash.%s' % UPWDCHG_PWHASH_ALGO.upper(), fromlist=['Cryptodome.Hash'], level=0)
            oHash = mHash.new(sPasswordNonce_secret.encode(UPWDCHG_ENCODING))
            byHash_compute = oHash.digest()
            dPasswordNonce_secret = { \
                'base64': B64.b64encode(byHash_compute).decode('ascii'), \
                'hash': { \
                    'algorithm': "%s-%s" % (UPWDCHG_PWHASH_METHOD, UPWDCHG_PWHASH_ALGO), \
                }, \
            }
        else:
            raise RuntimeError('invalid/unsupported password hash method; %s' % UPWDCHG_PWHASH_METHOD)

        # Session (hashed!)
        dSessionId = None
        if _sSessionId:
            if UPWDCHG_IDHASH_METHOD == 'hmac':
                mHash = __import__('Cryptodome.Hash.%s' % UPWDCHG_IDHASH_ALGO.upper(), fromlist=['Cryptodome.Hash'], level=0)
                byHashAlgo_salt = RANDOM.get_random_bytes(mHash.block_size)
                oHmac = HMAC.new(byHashAlgo_salt, _sSessionId.encode(UPWDCHG_ENCODING), mHash)
                byHash_compute = oHmac.digest()
                dSessionId = { \
                    'base64': B64.b64encode(byHash_compute).decode('ascii'), \
                    'hash': { \
                        'algorithm': "%s-%s" % (UPWDCHG_IDHASH_METHOD, UPWDCHG_IDHASH_ALGO), \
                        'salt': { \
                            'base64': B64.b64encode(byHashAlgo_salt).decode('ascii'), \
                        }, \
                    }, \
                }
            elif UPWDCHG_IDHASH_METHOD == 'hash':
                mHash = __import__('Cryptodome.Hash.%s' % UPWDCHG_IDHASH_ALGO.upper(), fromlist=['Cryptodome.Hash'], level=0)
                oHash = mHash.new(_sSessionId.encode(UPWDCHG_ENCODING))
                byHash_compute = oHash.digest()
                dSessionId = { \
                    'base64': B64.b64encode(byHash_compute).decode('ascii'), \
                    'hash': { \
                        'algorithm': "%s-%s" % (UPWDCHG_IDHASH_METHOD, UPWDCHG_IDHASH_ALGO), \
                    }, \
                }
            else:
                raise RuntimeError('invalid/unsupported session hash method; %s' % UPWDCHG_IDHASH_METHOD)

        # Data
        timeNow = gmtime()
        timeExpiration = gmtime(timegm(timeNow)+_iPasswordNonceTtl)
        self._dData = { \
            'type': 'password-nonce', \
            'timestamp': strftime('%Y-%m-%dT%H:%M:%SZ', timeNow), \
            'expiration': strftime('%Y-%m-%dT%H:%M:%SZ', timeExpiration), \
            'username': _sUsername, \
            'password-nonce-id': sPasswordNonce_id, \
            'password-nonce-secret': dPasswordNonce_secret, \
        }
        if dSessionId:
            self._dData['session-id'] = dSessionId
        self._sData = None


    def setData_PasswordChange(self, _sUsername, _sPasswordNew, _sPasswordOld, _sPasswordNonce=None, _sSessionId=None):
        """
        Sets the "password-change" token data
        """

        self._dData = { \
            'type': 'password-change', \
            'timestamp': strftime('%Y-%m-%dT%H:%M:%SZ', gmtime()), \
            'username': _sUsername, \
            'password-new': _sPasswordNew, \
            'password-old': _sPasswordOld, \
        }
        if _sPasswordNonce:
            self._dData['password-nonce'] = _sPasswordNonce
        if _sSessionId:
            self._dData['session-id'] = _sSessionId
        self._sData = None


    def setData_PasswordReset(self, _sUsername, _sPasswordNew, _sPasswordNonce, _sSessionId=None):
        """
        Sets the "password-reset" token data
        """

        self._dData = { \
            'type': 'password-reset', \
            'timestamp': strftime('%Y-%m-%dT%H:%M:%SZ', gmtime()), \
            'username': _sUsername, \
            'password-new': _sPasswordNew, \
            'password-nonce': _sPasswordNonce, \
        }
        if _sSessionId:
            self._dData['session-id'] = _sSessionId
        self._sData = None


    #
    # Getters
    #

    def __getitem__(self, key):
        return self._dData[key]


    def keys(self):
        return self._dData.keys()


    def _getDigestData(self, _dData=None):
        """
        Returns the token data, normalized for digest purposes
        """

        if _dData is None:
            _dData = self._dData
        return '|'.join([(lambda v: str(v) if not isinstance(v, dict) else self._getDigestData(v))(v) for k,v in sorted(_dData.items())])


    def getData(self, _bAsJson=False):
        """
        Returns the token (unicode) data (dictionary), mapping:
         'type': 'password-change'
         'timestamp': token creation timestamp
         'username': user name
         ... ; other type-dependent fields
        Or the corresponding JSON (string), if specified
        """

        if _bAsJson:
            if self._sData is None:
                self._sData = JSON.dumps(self._dData, indent=4)
            return self._sData
        return self._dData


    def getType(self):
        """
        Returns the token type (string)
        """

        return self._dData['type']


    #
    # Checkers
    #

    def checkData_Timestamp(self, _iTtl):
        """
        Checks the current token timestamp is within the given Time-to-Live period.
        Returns:
         0 on success
         1 on expired token
         Exception on internal failure
        """

        # Verify
        try:
            # ... timestamp
            if timegm(strptime(self._dData['timestamp'], '%Y-%m-%dT%H:%M:%SZ'))+_iTtl > timegm(gmtime()):
                return 0
        except Exception as e:
            raise RuntimeError('invalid token; %s' % str(e))
        return 1


    def checkData_Expiration(self):
        """
        Checks the current token expiration timestamp.
        Returns:
         0 on success
         1 on expired token
         Exception on internal failure
        """

        # Verify
        try:
            # ... expiration
            if strptime(self._dData['expiration'], '%Y-%m-%dT%H:%M:%SZ') > gmtime():
                return 0
        except Exception as e:
            raise RuntimeError('invalid token; %s' % str(e))
        return 1


    def checkData_PasswordNonce(self, _sUsername, _sPasswordNonce, _sSessionId=None):
        """
        Checks the current token is a valid "password-nonce" token for the given username/nonce.
        Returns/throws:
         0 on success
         1 on expired token
         2 on invalid secret
         3 on invalid session
         Exception on internal failure
        """

        # Normalize input
        (sPasswordNonce_id, sPasswordNonce_secret) = self.splitPasswordNonce(_sPasswordNonce)

        # Verify
        try:
            # ... type
            if self._dData['type'] != 'password-nonce':
                raise RuntimeError('invalid token type; %s' % self._dData['type'])
            # ... nonce ID
            if self._dData['password-nonce-id'] != sPasswordNonce_id:
                raise RuntimeError('mismatched nonce ID')
            # ... username
            if self._dData['username'] != _sUsername:
                raise RuntimeError('mismatched username')
            # ... secret
            byHash_given = B64.b64decode(self._dData['password-nonce-secret']['base64'].encode('ascii'))
            sHashAlgo = self._dData['password-nonce-secret']['hash']['algorithm']
            if sHashAlgo[:7] == 'pbkdf2-':
                byHashAlgo_salt = B64.b64decode(self._dData['password-nonce-secret']['hash']['salt']['base64'].encode('ascii'))
                iHashAlgo_iterations = int(self._dData['password-nonce-secret']['hash']['iterations'])
                mHash = __import__('Cryptodome.Hash.%s' % sHashAlgo[7:].upper(), fromlist=['Cryptodome.Hash'], level=0)
                byHash_compute = PBKDF2(
                    sPasswordNonce_secret.encode(UPWDCHG_ENCODING), byHashAlgo_salt,
                    len(byHash_given), iHashAlgo_iterations,
                    lambda p, s: HMAC.new(p, s, mHash).digest()
                )
            elif sHashAlgo[:5] == 'hmac-':
                byHashAlgo_salt = B64.b64decode(self._dData['password-nonce-secret']['hash']['salt']['base64'].encode('ascii'))
                mHash = __import__('Cryptodome.Hash.%s' % sHashAlgo[5:].upper(), fromlist=['Cryptodome.Hash'], level=0)
                oHmac = HMAC.new(byHashAlgo_salt, sPasswordNonce_secret.encode(UPWDCHG_ENCODING), mHash)
                byHash_compute = oHmac.digest()
            elif sHashAlgo[:5] == 'hash-':
                mHash = __import__('Cryptodome.Hash.%s' % sHashAlgo[5:].upper(), fromlist=['Cryptodome.Hash'], level=0)
                oHash = mHash.new(sPasswordNonce_secret.encode(UPWDCHG_ENCODING))
                byHash_compute = oHash.digest()
            else:
                raise RuntimeError('Invalid/unsupported password hash method; %s' % sHashAlgo)
            if byHash_given != byHash_compute:
                return 2
            # ... expiration
            if strptime(self._dData['expiration'], '%Y-%m-%dT%H:%M:%SZ') <= gmtime():
                return 1
            # ... session
            if 'session-id' in self._dData.keys():
                if not _sSessionId:
                    return 3
                byHash_given = B64.b64decode(self._dData['session-id']['base64'].encode('ascii'))
                sHashAlgo = self._dData['session-id']['hash']['algorithm']
                if sHashAlgo[:5] == 'hmac-':
                    byHashAlgo_salt = B64.b64decode(self._dData['session-id']['hash']['salt']['base64'].encode('ascii'))
                    mHash = __import__('Cryptodome.Hash.%s' % sHashAlgo[5:].upper(), fromlist=['Cryptodome.Hash'], level=0)
                    oHmac = HMAC.new(byHashAlgo_salt, _sSessionId.encode(UPWDCHG_ENCODING), mHash)
                    byHash_compute = oHmac.digest()
                elif sHashAlgo[:5] == 'hash-':
                    mHash = __import__('Cryptodome.Hash.%s' % sHashAlgo[5:].upper(), fromlist=['Cryptodome.Hash'], level=0)
                    oHash = mHash.new(_sSessionId.encode(UPWDCHG_ENCODING))
                    byHash_compute = oHash.digest()
                else:
                    raise RuntimeError('Invalid/unsupported session hash method; %s' % sHashAlgo)
                if byHash_given != byHash_compute:
                    return 3
            elif _sSessionId:
                return 3
        except Exception as e:
            raise RuntimeError('invalid "password-nonce" token; %s' % str(e))
        return 0
