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
 * CLASS
 ********************************************************************************/

final class testTokenData_PasswordNonce extends TestCase {
  protected $oUPwdChg;
  // protected $asToken;

  protected function setUp() {
    $this->oUPwdChg = new UPwdChg('./resources/config.php');
    // $asToken = phpUnitTest_callMethod($this->oUPwdChg, 'readToken', array('./tmp/password-nonce.token'));
    // $this->asToken = phpUnitTest_callMethod($this->oUPwdChg, 'decryptToken', array($asToken));
  }

  public function testValidButExpired() {
    $this->expectException(\Exception::class);
    $this->expectExceptionMessage($this->oUPwdChg->getText('error:expired_password_nonce'));
    phpUnitTest_callMethod($this->oUPwdChg, 'checkPasswordNonce', array('test-Benützername', 'test-Paßw0rt_nonce'));
  }

  public function testInvalidUsername() {
    $this->expectException(\Exception::class);
    $this->expectExceptionMessage($this->oUPwdChg->getText('error:invalid_password_nonce'));
    phpUnitTest_callMethod($this->oUPwdChg, 'checkPasswordNonce', array('wrong-Benützername', 'test-Paßw0rt_nonce'));
  }

  public function testInvalidId() {
    $this->expectException(\Exception::class);
    $this->expectExceptionMessage($this->oUPwdChg->getText('error:invalid_password_nonce'));
    phpUnitTest_callMethod($this->oUPwdChg, 'checkPasswordNonce', array('test-Benützername', 'wrong-Paßw0rt_nonce'));
  }

  public function testInvalidSecret() {
    $this->expectException(\Exception::class);
    $this->expectExceptionMessage($this->oUPwdChg->getText('error:invalid_password_nonce'));
    phpUnitTest_callMethod($this->oUPwdChg, 'checkPasswordNonce', array('test-Benützername', 'test-Paßw0rt_wrong'));
  }

}
