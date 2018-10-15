<?php // INDENTING (emacs/vi): -*- mode:php; tab-width:2; c-basic-offset:2; intent-tabs-mode:nil; -*- ex: set tabstop=2 expandtab:
/** Universal Password Changer (UPwdChg)
 *
 * Universal Password Changer (UPwdChg)
 * Copyright (C) 2014-2018 Cedric Dufour <http://cedric.dufour.name>
 * Author(s): Cedric Dufour <http://cedric.dufour.name>
 *
 * This file is part of the Universal Password Changer (UPwdChg).
 *
 * The Universal Password Changer (UPwdChg) is free software:
 * you can redistribute it and/or modify it under the terms of the GNU General
 * Public License as published by the Free Software Foundation, Version 3.
 *
 * The Universal Password Changer (UPwdChg) is distributed in the hope
 * that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * SPDX-License-Identifier: GPL-3.0
 * License-Filename: LICENSE/GPL-3.0.txt
 */


/*
 * DEPENDENCIES
 ********************************************************************************/

// UPwdChg
require_once('../frontend/UPwdChg.php');
require_once('./resources/phpunit-common.php');

// External
use PHPUnit\Framework\TestCase;


/*
 * CLASSES
 ********************************************************************************/

final class testTokenWriter extends TestCase {
  protected $oUPwdChg;

  protected function setUp() {
    $this->oUPwdChg = new UPwdChg('./resources/config.php');
  }

  public function testPasswordNonceRequest() {
    @unlink('./tmp/password-nonce-request.token');
    $asToken = phpUnitTest_callMethod($this->oUPwdChg, 'getTokenData_PasswordNonceRequest', array(time(), 'test-Benützername'));
    $asToken = phpUnitTest_callMethod($this->oUPwdChg, 'encryptToken', array($asToken));
    phpUnitTest_callMethod($this->oUPwdChg, 'writeToken', array(null, $asToken, './tmp/password-nonce-request.token'));
    $this->assertFileExists('./tmp/password-nonce-request.token');
    // Token to be tested using backend primitives
  }

  public function testPasswordChange() {
    @unlink('./tmp/password-change.token');
    $asToken = phpUnitTest_callMethod($this->oUPwdChg, 'getTokenData_PasswordChange', array(time(), 'test-Benützername', 'test-Paßw0rt_new', 'test-Paßw0rt_old', 'test-Paßw0rt_nonce'));
    $asToken = phpUnitTest_callMethod($this->oUPwdChg, 'encryptToken', array($asToken));
    phpUnitTest_callMethod($this->oUPwdChg, 'writeToken', array(null, $asToken, './tmp/password-change.token'));
    $this->assertFileExists('./tmp/password-change.token');
    // Token to be tested using backend primitives
  }

  public function testPasswordReset() {
    @unlink('./tmp/password-reset.token');
    $asToken = phpUnitTest_callMethod($this->oUPwdChg, 'getTokenData_PasswordReset', array(time(), 'test-Benützername', 'test-Paßw0rt_new', 'test-Paßw0rt_nonce'));
    $asToken = phpUnitTest_callMethod($this->oUPwdChg, 'encryptToken', array($asToken));
    phpUnitTest_callMethod($this->oUPwdChg, 'writeToken', array(null, $asToken, './tmp/password-reset.token'));
    $this->assertFileExists('./tmp/password-reset.token');
    // Token to be tested using backend primitives
  }

}
