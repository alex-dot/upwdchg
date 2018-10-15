<?php // INDENTING (emacs/vi): -*- mode:php; tab-width:2; c-basic-offset:2; intent-tabs-mode:nil; -*- ex: set tabstop=2 expandtab:
/*
 * HELPERS
 ********************************************************************************/

// REF: https://stackoverflow.com/questions/249664/best-practices-to-test-protected-methods-with-phpunit/8702347
function phpUnitTest_callMethod($oObject, $sMethod, array $amArguments) {
  $oClass = new \ReflectionClass($oObject);
  $oMethod = $oClass->getMethod($sMethod);
  $oMethod->setAccessible(true);
  return $oMethod->invokeArgs($oObject, $amArguments);
}
