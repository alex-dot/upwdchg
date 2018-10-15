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

final class testTokenReader_PasswordNonce extends TestCase {
  protected $oUPwdChg;
  protected $asToken;

  protected function setUp() {
    $this->oUPwdChg = new UPwdChg('./resources/config.php');
    $asToken = phpUnitTest_callMethod($this->oUPwdChg, 'readToken', array('./tmp/password-nonce.token'));
    $this->asToken = phpUnitTest_callMethod($this->oUPwdChg, 'decryptToken', array($asToken));
  }

  public function testType() {
    $this->assertArrayHasKey('type', $this->asToken);
    $this->assertSame('password-nonce', $this->asToken['type']);
  }

  public function testTimestamp() {
    $this->assertArrayHasKey('timestamp', $this->asToken);
    $this->assertRegExp('/^20[0-9]{2}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$/', $this->asToken['timestamp']);
  }

  public function testExpiration() {
    $this->assertArrayHasKey('expiration', $this->asToken);
    $this->assertRegExp('/^20[0-9]{2}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$/', $this->asToken['expiration']);
  }

  public function testUsername() {
    $this->assertArrayHasKey('username', $this->asToken);
    $this->assertSame('test-Benützername', $this->asToken['username']);
  }

  public function testPasswordNonceId() {
    $this->assertArrayHasKey('password-nonce-id', $this->asToken);
    $this->assertSame('test', $this->asToken['password-nonce-id']);
  }

  public function testPasswordNonceSecret() {
    $this->assertArrayHasKey('password-nonce-secret', $this->asToken);
  }

}
