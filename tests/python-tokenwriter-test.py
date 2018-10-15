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
    TokenWriter, \
    TokenReader

# Standard
from os import unlink
import unittest as UT
import sys


#------------------------------------------------------------------------------
# CLASSES
#------------------------------------------------------------------------------

class testTokenWriter_PasswordNonceRequest(UT.TestCase):

    def setUp(self):
        oToken = TokenWriter()
        oToken.config('./resources/frontend-private.pem', './resources/backend-public.pem')
        oToken.setData_PasswordNonceRequest('test-Benützername')
        self.assertEqual(oToken.writeToken('./tmp/password-nonce-request.token'), 0)
        self.oToken = TokenReader()
        self.oToken.config('./resources/backend-private.pem', './resources/frontend-public.pem')
        self.assertEqual(self.oToken.readToken('./tmp/password-nonce-request.token'), 0)

    def tearDown(self):
        unlink('./tmp/password-nonce-request.token')

    def testType(self):
        self.assertIn('type', self.oToken.keys())
        self.assertEqual(self.oToken['type'], 'password-nonce-request')

    def testTimestamp(self):
        self.assertIn('timestamp', self.oToken.keys())
        self.assertRegex(self.oToken['timestamp'], '^20[0-9]{2}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$')
        self.assertEqual(self.oToken.checkData_Timestamp(300), 0)

    def testUsername(self):
        self.assertIn('username', self.oToken.keys())
        self.assertEqual(self.oToken['username'], 'test-Benützername')


class testTokenWriter_PasswordChange(UT.TestCase):

    def setUp(self):
        oToken = TokenWriter()
        oToken.config('./resources/frontend-private.pem', './resources/backend-public.pem')
        oToken.setData_PasswordChange('test-Benützername', 'test-Paßw0rt_new', 'test-Paßw0rt_old', 'test-Paßw0rt_nonce')
        self.assertEqual(oToken.writeToken('./tmp/password-change.token'), 0)
        self.oToken = TokenReader()
        self.oToken.config('./resources/backend-private.pem', './resources/frontend-public.pem')
        self.assertEqual(self.oToken.readToken('./tmp/password-change.token'), 0)

    def tearDown(self):
        unlink('./tmp/password-change.token')

    def testType(self):
        self.assertIn('type', self.oToken.keys())
        self.assertEqual(self.oToken['type'], 'password-change')

    def testTimestamp(self):
        self.assertIn('timestamp', self.oToken.keys())
        self.assertRegex(self.oToken['timestamp'], '^20[0-9]{2}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$')
        self.assertEqual(self.oToken.checkData_Timestamp(300), 0)

    def testUsername(self):
        self.assertIn('username', self.oToken.keys())
        self.assertEqual(self.oToken['username'], 'test-Benützername')

    def testPasswordNew(self):
        self.assertIn('password-new', self.oToken.keys())
        self.assertEqual(self.oToken['password-new'], 'test-Paßw0rt_new')

    def testPasswordOld(self):
        self.assertIn('password-old', self.oToken.keys())
        self.assertEqual(self.oToken['password-old'], 'test-Paßw0rt_old')

    def testPasswordNonce(self):
        self.assertIn('password-nonce', self.oToken.keys())
        self.assertEqual(self.oToken['password-nonce'], 'test-Paßw0rt_nonce')


class testTokenWriter_PasswordReset(UT.TestCase):

    def setUp(self):
        oToken = TokenWriter()
        oToken.config('./resources/frontend-private.pem', './resources/backend-public.pem')
        oToken.setData_PasswordReset('test-Benützername', 'test-Paßw0rt_new', 'test-Paßw0rt_nonce')
        self.assertEqual(oToken.writeToken('./tmp/password-reset.token'), 0)
        self.oToken = TokenReader()
        self.oToken.config('./resources/backend-private.pem', './resources/frontend-public.pem')
        self.assertEqual(self.oToken.readToken('./tmp/password-reset.token'), 0)

    def tearDown(self):
        unlink('./tmp/password-reset.token')

    def testType(self):
        self.assertIn('type', self.oToken.keys())
        self.assertEqual(self.oToken['type'], 'password-reset')

    def testTimestamp(self):
        self.assertIn('timestamp', self.oToken.keys())
        self.assertRegex(self.oToken['timestamp'], '^20[0-9]{2}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$')
        self.assertEqual(self.oToken.checkData_Timestamp(300), 0)

    def testUsername(self):
        self.assertIn('username', self.oToken.keys())
        self.assertEqual(self.oToken['username'], 'test-Benützername')

    def testPasswordNew(self):
        self.assertIn('password-new', self.oToken.keys())
        self.assertEqual(self.oToken['password-new'], 'test-Paßw0rt_new')

    def testPasswordNonce(self):
        self.assertIn('password-nonce', self.oToken.keys())
        self.assertEqual(self.oToken['password-nonce'], 'test-Paßw0rt_nonce')


class testTokenWriter_PasswordNonce(UT.TestCase):

    def setUp(self):
        oToken = TokenWriter()
        oToken.config('./resources/backend-private.pem', './resources/frontend-public.pem')
        oToken.setData_PasswordNonce('test-Benützername', 'test-Paßw0rt_nonce', 300)
        self.assertEqual(oToken.writeToken('./tmp/password-nonce.token'), 0)
        self.oToken = TokenReader()
        self.oToken.config('./resources/frontend-private.pem', './resources/backend-public.pem')
        self.assertEqual(self.oToken.readToken('./tmp/password-nonce.token'), 0)

    def tearDown(self):
        unlink('./tmp/password-nonce.token')

    def testType(self):
        self.assertIn('type', self.oToken.keys())
        self.assertEqual(self.oToken['type'], 'password-nonce')

    def testTimestamp(self):
        self.assertIn('timestamp', self.oToken.keys())
        self.assertRegex(self.oToken['timestamp'], '^20[0-9]{2}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$')
        self.assertEqual(self.oToken.checkData_Timestamp(300), 0)

    def testExpiration(self):
        self.assertIn('expiration', self.oToken.keys())
        self.assertRegex(self.oToken['expiration'], '^20[0-9]{2}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$')
        self.assertEqual(self.oToken.checkData_Expiration(), 0)

    def testUsername(self):
        self.assertIn('username', self.oToken.keys())
        self.assertEqual(self.oToken['username'], 'test-Benützername')

    def testPasswordNonceId(self):
        self.assertIn('password-nonce-id', self.oToken.keys())
        self.assertEqual(self.oToken['password-nonce-id'], 'test')

    def testPasswordNonceSecret(self):
        self.assertIn('password-nonce-secret', self.oToken.keys())

    def testPasswordNonce(self):
        self.assertIn(self.oToken.checkData_PasswordNonce('test-Benützername', 'test-Paßw0rt_nonce'), (0,1))
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
    oTestSuite.addTest(UT.makeSuite(testTokenWriter_PasswordNonceRequest))
    oTestSuite.addTest(UT.makeSuite(testTokenWriter_PasswordChange))
    oTestSuite.addTest(UT.makeSuite(testTokenWriter_PasswordReset))
    oTestSuite.addTest(UT.makeSuite(testTokenWriter_PasswordNonce))
    oTestResult = UT.TextTestRunner(verbosity=2).run(oTestSuite)
    sys.exit(0 if oTestResult.wasSuccessful() else 1)

