#!/usr/bin/env python3
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
    TokenReader, \
    TokenWriter

# Standard
import unittest as UT
import sys


#------------------------------------------------------------------------------
# CLASSES
#------------------------------------------------------------------------------

class testTokenData_SetData(UT.TestCase):

    def setUp(self):
        self.oToken = TokenWriter()

    def testPasswordNonceRequest(self):
        self.oToken.setData_PasswordNonceRequest('test-Benützername')

    def testPasswordChange(self):
        self.oToken.setData_PasswordChange('test-Benützername', 'test-Paßw0rt_new', 'test-Paßw0rt_old', 'test-Paßw0rt_nonce')

    def testPasswordReset(self):
        self.oToken.setData_PasswordReset('test-Benützername', 'test-Paßw0rt_new', 'test-Paßw0rt_nonce')

    def testPasswordNonce(self):
        sNonce = self.oToken.makePasswordNonce([6, 6])
        self.assertRegex(sNonce, '^[A-Za-z0-9]{6}-[A-Za-z0-9]{6}$')
        lsNonce = self.oToken.splitPasswordNonce('test-Paßw0rt_nonce')
        self.assertListEqual(lsNonce, ['test', 'Paßw0rt_nonce'])
        self.oToken.setData_PasswordNonce('test-Benützername', 'test-Paßw0rt_nonce', 300)


class testTokenData_ReadToken(UT.TestCase):

    def setUp(self):
        self.oToken = TokenReader()

    def testPasswordNonce(self):
        self.oToken.config('./resources/frontend-private.pem', './resources/backend-public.pem')
        self.assertEqual(self.oToken.readToken('./tmp/password-nonce.token'), 0)


class testTokenData_CheckData(UT.TestCase):

    def setUp(self):
        self.oToken = TokenReader()
        self.oToken.config('./resources/frontend-private.pem', './resources/backend-public.pem')
        if(self.oToken.readToken('./tmp/password-nonce.token')):
            self.skipTest('Failed to read token')

    def testTimestamp(self):
        self.assertEqual(self.oToken.checkData_Timestamp(9999999999), 0)
        self.assertEqual(self.oToken.checkData_Timestamp(0), 1)

    def testExpiration(self):
        self.assertIn(self.oToken.checkData_Expiration(), (0, 1))

    def testPasswordNonce(self):
        self.assertEqual(self.oToken.checkData_PasswordNonce('test-Benützername', 'test-Paßw0rt_nonce'), 1)
        self.assertEqual(self.oToken.checkData_PasswordNonce('test-Benützername', 'test-Paßw0rt_wrong'), 2)
        with self.assertRaises(RuntimeError):
            self.oToken.checkData_PasswordNonce('wrong-Benützername', 'test-Paßw0rt_nonce')
        with self.assertRaises(RuntimeError):
            self.oToken.checkData_PasswordNonce('test-Benützername', 'wrong-Paßw0rt_nonce')


#------------------------------------------------------------------------------
# MAIN
#------------------------------------------------------------------------------

if __name__ == '__main__':
    #UT.main()
    oTestSuite = UT.TestSuite()
    oTestSuite.addTest(UT.makeSuite(testTokenData_SetData))
    oTestSuite.addTest(UT.makeSuite(testTokenData_ReadToken))
    oTestSuite.addTest(UT.makeSuite(testTokenData_CheckData))
    oTestResult = UT.TextTestRunner(verbosity=2).run(oTestSuite)
    sys.exit(0 if oTestResult.wasSuccessful() else 1)

