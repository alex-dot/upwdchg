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
# ... deb: python-m2crypto, python-passlib
from UPwdChg import \
    UPWDCHG_ENCODING, \
    UPWDCHG_DEFAULT_FILE_RANDOM, \
    UPWDCHG_PWHASH_METHOD, \
    UPWDCHG_PWHASH_ALGO, \
    UPWDCHG_PWHASH_KEY_LENGTH, \
    UPWDCHG_PWHASH_SALT_LENGTH, \
    UPWDCHG_PWHASH_ITERATIONS
import base64 as B64
from calendar import \
    timegm
import json as JSON
import M2Crypto as M2C
import passlib.crypto.digest as PL
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

    def makePasswordNonce(self, _liPasswordNonceLength, _bSplit=False, _sFileRandom=UPWDCHG_DEFAULT_FILE_RANDOM):
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
        M2C.Rand.load_file(_sFileRandom, 2*iPasswordNonceLength_total)
        sPasswordNonce = B64.b64encode(M2C.Rand.rand_bytes(2*iPasswordNonceLength_total), '**').rstrip('=').replace('*', '')
        sPasswordNonce_id = sPasswordNonce[0:iPasswordNonceLength_id]
        sPasswordNonce_secret = sPasswordNonce[iPasswordNonceLength_id:iPasswordNonceLength_total]
        if _bSplit:
            return [sPasswordNonce_id, sPasswordNonce_secret]
        return sPasswordNonce_id+'-'+sPasswordNonce_secret


    def splitPasswordNonce(self, _suPasswordNonce):
        """
        Splits the password nonce into its ID and secret components
        """

        uPasswordNonce = _suPasswordNonce if isinstance(_suPasswordNonce, unicode) else _suPasswordNonce.decode(UPWDCHG_ENCODING)
        return uPasswordNonce.split('-', 1)


    #
    # Setters
    #

    def setData_PasswordNonceRequest(self, _suUsername):
        """
        Sets the "password-nonce-request" token data
        """

        self._dData = { \
            'type': 'password-nonce-request', \
            'timestamp': unicode(strftime('%Y-%m-%dT%H:%M:%SZ', gmtime())), \
            'username': _suUsername if isinstance(_suUsername, unicode) else _suUsername.decode(UPWDCHG_ENCODING), \
        }
        self._sData = None


    def setData_PasswordNonce(self, _suUsername, _suPasswordNonce, _iPasswordNonceTtl):
        """
        Sets the "password-nonce" token data
        """

        # Split password nonce
        (uPasswordNonce_id, uPasswordNonce_secret) = self.splitPasswordNonce(_suPasswordNonce)

        # Secret (hashed!)
        if UPWDCHG_PWHASH_METHOD == 'pbkdf2':
            sHashAlgo_salt = M2C.Rand.rand_bytes(UPWDCHG_PWHASH_SALT_LENGTH)
            sHash_compute = PL.pbkdf2_hmac(UPWDCHG_PWHASH_ALGO, uPasswordNonce_secret, sHashAlgo_salt, UPWDCHG_PWHASH_ITERATIONS, UPWDCHG_PWHASH_KEY_LENGTH)
            dPasswordNonce_secret = { \
                'base64': B64.b64encode(sHash_compute), \
                'hash': { \
                    'algorithm': "%s-%s" % (UPWDCHG_PWHASH_METHOD, UPWDCHG_PWHASH_ALGO), \
                    'salt': { \
                        'base64': B64.b64encode(sHashAlgo_salt), \
                    }, \
                    'iterations': UPWDCHG_PWHASH_ITERATIONS, \
                }, \
            }
        else:
            # (for the time being...)
            raise RuntimeError('invalid/unsupported password hash method; %s' % UPWDCHG_PWHASH_METHOD)

        # Data
        timeNow = gmtime()
        timeExpiration = gmtime(timegm(timeNow)+_iPasswordNonceTtl)
        self._dData = { \
            'type': 'password-nonce', \
            'timestamp': unicode(strftime('%Y-%m-%dT%H:%M:%SZ', timeNow)), \
            'expiration': unicode(strftime('%Y-%m-%dT%H:%M:%SZ', timeExpiration)), \
            'username': _suUsername if isinstance(_suUsername, unicode) else _suUsername.decode(UPWDCHG_ENCODING), \
            'password-nonce-id': uPasswordNonce_id, \
            'password-nonce-secret': dPasswordNonce_secret, \
        }
        self._sData = None


    def setData_PasswordChange(self, _suUsername, _suPasswordNew, _suPasswordOld, _suPasswordNonce=None):
        """
        Sets the "password-change" token data
        """

        self._dData = { \
            'type': 'password-change', \
            'timestamp': unicode(strftime('%Y-%m-%dT%H:%M:%SZ', gmtime())), \
            'username': _suUsername if isinstance(_suUsername, unicode) else _suUsername.decode(UPWDCHG_ENCODING), \
            'password-new': _suPasswordNew if isinstance(_suPasswordNew, unicode) else _suPasswordNew.decode(UPWDCHG_ENCODING), \
            'password-old': _suPasswordOld if isinstance(_suPasswordOld, unicode) else _suPasswordOld.decode(UPWDCHG_ENCODING), \
        }
        if _suPasswordNonce:
            self._dData['password-nonce'] = _suPasswordNonce if isinstance(_suPasswordNonce, unicode) else _suPasswordNonce.decode(UPWDCHG_ENCODING)
        self._sData = None


    def setData_PasswordReset(self, _suUsername, _suPasswordNew, _suPasswordNonce):
        """
        Sets the "password-reset" token data
        """

        self._dData = { \
            'type': 'password-reset', \
            'timestamp': unicode(strftime('%Y-%m-%dT%H:%M:%SZ', gmtime())), \
            'username': _suUsername if isinstance(_suUsername, unicode) else _suUsername.decode(UPWDCHG_ENCODING), \
            'password-new': _suPasswordNew if isinstance(_suPasswordNew, unicode) else _suPasswordNew.decode(UPWDCHG_ENCODING), \
            'password-nonce': _suPasswordNonce if isinstance(_suPasswordNonce, unicode) else _suPasswordNonce.decode(UPWDCHG_ENCODING), \
        }
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
        return '|'.join([(lambda v: unicode(v) if not isinstance(v, dict) else self._getDigestData(v))(v) for k,v in sorted(_dData.items())])


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
            if timegm(strptime(self._dData['timestamp'], '%Y-%m-%dT%H:%M:%SZ')) > timegm(gmtime())+_iTtl:
                return 1
        except Exception as e:
            raise RuntimeError('invalid token; %s' % str(e))
        return 0


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
            # ... timestamp
            if timegm(strptime(self._dData['expiration'], '%Y-%m-%dT%H:%M:%SZ')) > timegm(gmtime()):
                return 1
        except Exception as e:
            raise RuntimeError('invalid token; %s' % str(e))
        return 0


    def checkData_PasswordNonce(self, _suUsername, _suPasswordNonce):
        """
        Checks the current token is a valid "password-nonce" token for the given username/nonce.
        Returns/throws:
         0 on success
         1 on expired token
         2 on invalid secret
         Exception on internal failure
        """

        # Normalize input
        uUsername = _suUsername if isinstance(_suUsername, unicode) else _suUsername.decode(UPWDCHG_ENCODING)
        (uPasswordNonce_id, uPasswordNonce_secret) = self.splitPasswordNonce(_suPasswordNonce)

        # Verify
        try:
            # ... type
            if self._dData['type'] != 'password-nonce':
                raise RuntimeError('invalid token type; %s' % self._dData['type'])
            # ... nonce ID
            if self._dData['password-nonce-id'] != uPasswordNonce_id:
                raise RuntimeError('mismatched nonce ID')
            # ... username
            if self._dData['username'] != uUsername:
                raise RuntimeError('mismatched username')
            # ... secret
            sHash_given = B64.b64decode(self._dData['password-nonce-secret']['base64'])
            sHashAlgo = self._dData['password-nonce-secret']['hash']['algorithm']
            if sHashAlgo[:7] == 'pbkdf2-':
                sHashAlgo_salt = B64.b64decode(self._dData['password-nonce-secret']['hash']['salt']['base64'])
                iHashAlgo_iterations = int(self._dData['password-nonce-secret']['hash']['iterations'])
                sHash_compute = PL.pbkdf2_hmac(sHashAlgo[7:], uPasswordNonce_secret, sHashAlgo_salt, iHashAlgo_iterations, len(sHash_given))
            else:
                raise RuntimeError('Invalid/unsupported password hash method; %s' % sHashAlgo)
            if sHash_given != sHash_compute:
                return 2
            # ... expiration
            if timegm(strptime(self._dData['expiration'], '%Y-%m-%dT%H:%M:%SZ')) <= timegm(gmtime()):
                return 1
        except Exception as e:
            raise RuntimeError('invalid "password-nonce" token; %s' % str(e))
        return 0
