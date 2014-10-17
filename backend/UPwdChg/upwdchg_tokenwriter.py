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

    def __init__( self ):
        TokenData.__init__( self )

        # Fields
        self.error = 0


    #------------------------------------------------------------------------------
    # METHODS
    #------------------------------------------------------------------------------

    #
    # Error handling
    #

    def __ERROR( self, _sMessage, _iError ):
        self.error = _iError
        sys.stderr.write( 'ERROR[TokenWriter]: %s\n' % _sMessage )


    #
    # Data
    #

    def write( self, _sFileToken, _sFilePublicKey, _sFileRandom ):
        """
        Builds, encrypts and writes a UPwdChg token; returns a non-zero exit code in case of failure.
        """

        # Initialization
        self.error = 0

        # Random material
        try:
            M2C.Rand.load_file( _sFileRandom, UPWDCHG_CIPHER_KEY_LENGTH+UPWDCHG_CIPHER_IV_LENGTH )
        except Exception as e:
            self.__ERROR( 'Failed to seed random number generator; %s' % str( e ), 1001 )
            return self.error
        __sCipherKey = M2C.Rand.rand_bytes( UPWDCHG_CIPHER_KEY_LENGTH, );
        __sCipherIv = M2C.Rand.rand_bytes( UPWDCHG_CIPHER_IV_LENGTH, );

        # Load the RSA public key
        try:
            __oPublicKey = M2C.RSA.load_pub_key( _sFilePublicKey )
        except Exception as e:
            self.__ERROR( 'Failed to load RSA public key; %s' % str( e ), 1011 )
            return self.error

        # Encrypt the (symmetric) data key and initialization vector (IV)
        try:
            __sCipherKeyIvEncrypted = __oPublicKey.public_encrypt( __sCipherKey+__sCipherIv, M2C.RSA.pkcs1_padding )
        except Exception as e:
            self.__ERROR( 'Failed to encrypt data key/IV; %s' % str( e ), 1021 )
            return self.error

        # Data
        __sData = '\n'.join( map( lambda _u:_u.encode('utf-8'), [ self._uTimestamp, self._uUsername, self._uPasswordOld, self._uPasswordNew ] ) )
        try:
            __oMessageDigest = M2C.EVP.MessageDigest( algo=UPWDCHG_DIGEST_ALGO )
        except Exception as e:
            self.__ERROR( 'Failed to initialize data digest; %s' % str( e ), 1031 )
            return self.error
        if __oMessageDigest.update( __sData ) != 1:
            self.__ERROR( 'Failed to compute data digest', 1032 )
            return self.error
        __sDataDigest = __oMessageDigest.final()
        __sData = B64.b64encode( __sDataDigest )+'\n'+__sData


        # Encrypt the data
        try:
            __oCipher = M2C.EVP.Cipher( alg=UPWDCHG_CIPHER_ALGO, key=__sCipherKey, iv=__sCipherIv, op=M2C.encrypt )
        except Exception as e:
            self.__ERROR( 'Failed to initialize data encryption; %s' % str( e ), 1041 )
            return self.error
        try:
            __sDataEncrypted = __oCipher.update( __sData )
            __sDataEncrypted += __oCipher.final()
        except Exception as e:
            self.__ERROR( 'Failed to encrypt data; %s' % str( e ), 1042 )
            return self.error

        # Write the token
        __sToken = '# UNIVERSAL PASSWORD CHANGER TOKEN, V1.0\n'
        __sToken += B64.b64encode( __sCipherKeyIvEncrypted )+'\n'
        __sToken += B64.b64encode( __sDataEncrypted )+'\n'
        try:
            if _sFileToken == '-':
                __oFile = sys.stdout
            else:
                __oFile = open( _sFileToken, 'w' )
        except Exception as e:
            self.__ERROR( 'Failed to open token file; %s' % str( e ), 1051 )
            return self.error
        try:
            __oFile.write( __sToken )
        except Exception as e:
            self.__ERROR( 'Failed to write token to file; %s' % str( e ), 1052 )
        if __oFile != sys.stdout:
            __oFile.close()
        if self.error:
            return self.error

        # Done
        return 0

