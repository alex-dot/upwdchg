<?php // INDENTING (emacs/vi): -*- mode:php; tab-width:2; c-basic-offset:2; intent-tabs-mode:nil; -*- ex: set tabstop=2 expandtab:
/** Universal Password Changer (UPwdChg)
 *
 * <P><B>COPYRIGHT:</B></P>
 * <PRE>
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
 * </PRE>
 *
 * @package    UPwdChg
 * @subpackage Main
 * @copyright  2014 Cedric Dufour <http://cedric.dufour.name>
 * @author     Cedric Dufour <http://cedric.dufour.name>
 * @license    http://www.gnu.org/licenses/gpl-3.0.html GNU General Public License (GPL) Version 3
 * @version    @version@
 * @link       http://cedric.dufour.name/software/upwdchg
 */

/** Universal Password Changer (UPwdChg) Module
 *
 * @package    UPwdChg
 * @subpackage Main
 */
class UPwdChg
{

  /*
   * CONSTANTS
   ********************************************************************************/

  /** Symetric cipher algorithm (OpenSSL stanza)
   * @var string */
  const CIPHER_ALGO = 'aes-256-cbc';

  /** Symetric cipher key length
   * @var int */
  const CIPHER_KEY_LENGTH = 32;

  /** Symetric cipher IV length
   * @var int */
  const CIPHER_IV_LENGTH = 16;

  /** Digest algorithm (HASH stanza)
   * @var string */
  const DIGEST_ALGO = 'sha256';

  /** Input (GET/POST) maximum length
   * @var int */
  const INPUT_MAX_LENGTH = 100;


  /*
   * FIELDS
   ********************************************************************************/

  /** Configuration parameters
   * @var array|mixed */
  private $amCONFIG;

  /** Form data
   * @var array|mixed */
  private $amFORMDATA;

  /** Remote IP
   * @var string */
  private $sRemoteIP;


  /*
   * CONSTRUCTORS
   ********************************************************************************/

  /** Construct and inititalize a new UPwdChg object
   *
   * @param string $sConfigurationPath Configuration file path
   */
  public function __construct($sConfigurationPath) {
    // Fields
    // ... comfiguration
    $this->initConfig($sConfigurationPath);
    // ... remote IP
    $this->sRemoteIP = 'unknown';
    if(isset( $_SERVER['HTTP_X_FORWARDED_FOR'] )) {
      $this->sRemoteIP = $_SERVER['HTTP_X_FORWARDED_FOR'];
    }
    elseif(isset( $_SERVER['REMOTE_ADDR'] )) {
      $this->sRemoteIP = $_SERVER['REMOTE_ADDR'];
    }
  }


  /*
   * METHODS: General
   ********************************************************************************/

  /** Initialize (default or user-overriden) configuration parameters for this object
   *
   * @param string $sConfigurationPath Configuration file path (see the sample <SAMP>config.php</SAMP> file for further details)
   * @return array|mixed View data
   */
  private function initConfig($sConfigurationPath) {
    // Set defaults
    $_CONFIG = array();
    $_CONFIG['locales'] = 'en,fr';
    $_CONFIG['force_ssl'] = 1;
    $_CONFIG['strict_session'] = 1;
    $_CONFIG['resources_directory'] = dirname(__FILE__).'/data/UPwdChg/resources';
    $_CONFIG['tokens_directory_private'] = '/var/lib/upwdchg/tokens/private.d';
    $_CONFIG['tokens_directory_public'] = '/var/lib/upwdchg/tokens/public.d';
    $_CONFIG['public_key_file'] = '/etc/upwdchg/public.pem';
    $_CONFIG['random_source'] = MCRYPT_DEV_URANDOM;
    $_CONFIG['authentication_method'] = 'http';
    $_CONFIG['authentication_exempt'] = array();
    $_CONFIG['credentials_check_method'] = 'ldap';
    $_CONFIG['password_nonce'] = 0;
    $_CONFIG['password_reset'] = 0;
    $_CONFIG['password_length_minimum'] = 8;
    $_CONFIG['password_length_maximum'] = 64;
    $_CONFIG['password_charset_forbidden'] = '';
    $_CONFIG['password_charset_notascii'] = -1;
    $_CONFIG['password_type_lower'] = 0;
    $_CONFIG['password_type_upper'] = 0;
    $_CONFIG['password_type_digit'] = 0;
    $_CONFIG['password_type_punct'] = 0;
    $_CONFIG['password_type_other'] = 0;
    $_CONFIG['password_type_minimum'] = 0;
    $_CONFIG['ldap_host'] = 'ldap://ldap.example.org';
    $_CONFIG['ldap_port'] = 389;
    $_CONFIG['ldap_user_dn'] = 'uid=%{USERNAME},ou=users,dc=example,dc=org';
    $_CONFIG['ldap_user_base_dn'] = 'ou=users,dc=example,dc=org';
    $_CONFIG['ldap_user_search_scope'] = 'one';
    $_CONFIG['ldap_user_filter'] = '(&(objectClass=*)(uid=%{USERNAME}))';
    $_CONFIG['ldap_bind_dn'] = '';
    $_CONFIG['ldap_bind_password'] = '';
    $_CONFIG['ldap_protocol_version'] = 0;
    $_CONFIG['captcha_width'] = 240;
    $_CONFIG['captcha_height'] = 120;
    $_CONFIG['captcha_fontsize'] = 32;
    $_CONFIG['captcha_ttl'] = 10;

    // Load user configuration
    if((include $sConfigurationPath) === false) {
      trigger_error('['.__METHOD__.'] Failed to load configuration', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }

    // Validation
    //echo nl2br(var_export($_CONFIG, true)); // DEBUG
    // ... is integer
    foreach(array('force_ssl', 'strict_session', 'random_source', 'password_nonce', 'password_reset',
                  'password_length_minimum', 'password_length_maximum', 'password_charset_notascii',
                  'password_type_lower', 'password_type_upper', 'password_type_digit',
                  'password_type_punct', 'password_type_other', 'password_type_minimum',
                  'ldap_port', 'ldap_protocol_version',
                  'captcha_width', 'captcha_height', 'captcha_fontsize', 'captcha_ttl',
    ) as $p)
      if(!is_int($_CONFIG[$p]))
        trigger_error('['.__METHOD__.'] Parameter must be an integer ('.$p.')', E_USER_ERROR);
    // ... is string
    foreach(array('locales', 'authentication_method', 'credentials_check_method', 'password_charset_forbidden',
                  'ldap_host', 'ldap_user_dn', 'ldap_user_base_dn', 'ldap_user_search_scope',
                  'ldap_user_filter', 'ldap_bind_dn', 'ldap_bind_password',
    ) as $p)
      if(!is_string($_CONFIG[$p]))
        trigger_error('['.__METHOD__.'] Parameter must be a string ('.$p.')', E_USER_ERROR);
    // ... is array
    foreach(array('authentication_exempt') as $p)
      if(!is_array($_CONFIG[$p]))
        trigger_error('['.__METHOD__.'] Parameter must be an array ('.$p.')', E_USER_ERROR);
    // ... is readable
    foreach(array('resources_directory', 'tokens_directory_public', 'public_key_file') as $p)
      if(!is_readable($_CONFIG[$p]))
        trigger_error('['.__METHOD__.'] Parameter must be a readable path ('.$p.')', E_USER_ERROR);
    // ... is writeable
    foreach(array('tokens_directory_private') as $p)
      if(!is_writable($_CONFIG[$p]))
        trigger_error('['.__METHOD__.'] Parameter must be a writable path ('.$p.')', E_USER_ERROR);

    // Done
    $this->amCONFIG = $_CONFIG;
  }

  /** Retrieve the supported locales
   *
   * @return array|string Array of locale IDs
   */
  public function getSupportedLocales() {
    return explode(',', $this->amCONFIG['locales']);
  }

  /** Retrieve the default locale
   *
   * @return string Locale ID
   */
  public function getDefaultLocale() {
    static $sLocale;
    if(is_null($sLocale)) {
      $i = strpos($this->amCONFIG['locales'], ',');
      if($i === false)
        $sLocale = $this->amCONFIG['locales'];
      else
        $sLocale = substr($this->amCONFIG['locales'], 0, $i);
    }
    return $sLocale;
  }

  /** Retrieve the current locale
   *
   * @return string Locale ID
   */
  public function getCurrentLocale() {
    static $sLocale;
    if(is_null($sLocale)) {
      if(isset($_SESSION['UPwdChg_Locale']))
        $sLocale = $_SESSION['UPwdChg_Locale'];
      else
        $sLocale = $this->getDefaultLocale();
    }
    return $sLocale;
  }

  /** Retrieve the resources directory path
   *
   * @return string Directory path
   */
  public function getResourcesDirectory() {
    return $this->amCONFIG['resources_directory'];
  }

  /** Password nonce feature status
   *
   *  Returns whether password nonce feature is enabled
   */
  public function hasPasswordNonce() {
    return $this->amCONFIG['password_nonce'];
  }

  /** Retrieve the reset URL (in case of internal error)
   *
   * @return string Reset URL
   */
  public function getResetURL() {
    return '?';
  }

  /** Retrieve (localized) text
   *
   * @param string $sTextID Text ID
   * @return string Text
   */
  public function getText($sTextID) {
    static $_TEXT;

    // Initialize message array
    if(is_null($_TEXT)) {
      // Default (English messages)
      $_TEXT = array();
      $_TEXT['title'] = 'Password Change';
      $_TEXT['label:language'] = 'Language';
      $_TEXT['label:captcha'] = 'Captcha';
      $_TEXT['label:username'] = 'Username';
      $_TEXT['label:password_old'] = 'Old Password';
      $_TEXT['label:password_new'] = 'New Password';
      $_TEXT['label:password_confirm'] = '(confirm)';
      $_TEXT['label:password_policy'] = '(password policy)';
      $_TEXT['label:password_policy_back'] = '(back)';
      $_TEXT['label:password_reset'] = 'Password forgotten ? Please proceed to password reset...';
      $_TEXT['label:password_nonce'] = 'PIN code';
      $_TEXT['label:submit'] = 'Submit';
      $_TEXT['label:reset'] = '(start over)';
      $_TEXT['error:internal_error'] = 'Internal error. Please contact the system administrator.';
      $_TEXT['error:unsecure_channel'] = 'Unsecure channel. Please use an encrypted channel (SSL).';
      $_TEXT['error:invalid_session'] = 'Invalid session. Please start over.';
      $_TEXT['error:invalid_form_data'] = 'Invalid form data. Please contact the system administrator.';
      $_TEXT['error:invalid_captcha'] = 'Invalid captcha.';
      $_TEXT['error:invalid_credentials'] = 'Invalid credentials (incorrect username or old password).';
      $_TEXT['error:invalid_password_nonce'] = 'Invalid PIN code.';
      $_TEXT['error:expired_password_nonce'] = 'PIN code has expired.';
      $_TEXT['error:password_mismatch'] = 'Password confirmation mismatch.';
      $_TEXT['error:password_identical'] = 'Old and new passwords are identical.';
      $_TEXT['error:password_length_minimum'] = 'Password MUST contain at least '.$this->amCONFIG['password_length_minimum'].' characters.';
      $_TEXT['error:password_length_maximum'] = 'Password may NOT contain more than '.$this->amCONFIG['password_length_maximum'].' characters.';
      $_TEXT['error:password_charset_forbidden'] = 'Password may NOT contain any forbidden character.';
      $_TEXT['error:password_charset_notascii_required'] = 'Password MUST contain at least one non-ASCII character.';
      $_TEXT['error:password_charset_notascii_forbidden'] = 'Password may NOT contain any non-ASCII character.';
      $_TEXT['error:password_type_lower_required'] = 'Password MUST contain at least one lowercase character.';
      $_TEXT['error:password_type_lower_forbidden'] = 'Password may NOT contain any lowercase character.';
      $_TEXT['error:password_type_upper_required'] = 'Password MUST contain at least one uppercase character.';
      $_TEXT['error:password_type_upper_forbidden'] = 'Password may NOT contain any uppercase character.';
      $_TEXT['error:password_type_digit_required'] = 'Password MUST contain at least one digit.';
      $_TEXT['error:password_type_digit_forbidden'] = 'Password may NOT contain any digit.';
      $_TEXT['error:password_type_punct_required'] = 'Password MUST contain at least one punctuation mark.';
      $_TEXT['error:password_type_punct_forbidden'] = 'Password may NOT contain any punctuation mark.';
      $_TEXT['error:password_type_other_required'] = 'Password MUST contain at least one special character.';
      $_TEXT['error:password_type_other_forbidden'] = 'Password may NOT contain any special character.';
      $_TEXT['error:password_type_minimum'] = 'Password MUST contain at least '.$this->amCONFIG['password_type_minimum'].' different character types.';
      $_TEXT['info:password_nonce_request'] = 'Request successfully sent. You should receive your PIN code shortly.';
      $_TEXT['info:password_charset_forbidden'] = 'Password may NOT contain the following forbidden characters: '.str_replace(' ', '(space)', $this->amCONFIG['password_charset_forbidden']);
      $_TEXT['info:password_charset_notascii'] = 'Password MAY contain non-ASCII characters.';
      $_TEXT['info:password_type_lower'] = 'Password MAY contain lowercase characters.';
      $_TEXT['info:password_type_upper'] = 'Password MAY contain uppercase characters.';
      $_TEXT['info:password_type_digit'] = 'Password MAY contain digits.';
      $_TEXT['info:password_type_punct'] = 'Password MAY contain punctuation marks.';
      $_TEXT['info:password_type_other'] = 'Password MAY contain special characters.';

      // Include localized messages
      $sLocale = $this->getCurrentLocale();
      if($sLocale != 'en')
        include_once $this->amCONFIG['resources_directory'].'/'.$sLocale.'/text.php';
    }

    // Done
    return $_TEXT[$sTextID];
  }

  /** Add given message in error messages stack
   *
   * @param string $sError Error message
   */
  private function errorAdd($sError) {
    $_SESSION['UPwdChg_Error'] = isset($_SESSION['UPwdChg_Error']) ? $_SESSION['UPwdChg_Error']."\n".$sError : $sError;
  }

  /** Retrieve message from error messages stack
   *
   * @return string Error message
   */
  private function errorGet() {
    $sError = isset($_SESSION['UPwdChg_Error']) ? $_SESSION['UPwdChg_Error'] : null;
    unset($_SESSION['UPwdChg_Error']);
    return $sError;
  }

  /** Add given message in informational messages stack
   *
   * @param string $sInfo Error message
   */
  private function infoAdd($sInfo) {
    $_SESSION['UPwdChg_Info'] = isset($_SESSION['UPwdChg_Info']) ? $_SESSION['UPwdChg_Info']."\n".$sInfo : $sInfo;
  }

  /** Retrieve message from informational messages stack
   *
   * @return string Error message
   */
  private function infoGet() {
    $sInfo = isset($_SESSION['UPwdChg_Info']) ? $_SESSION['UPwdChg_Info'] : null;
    unset($_SESSION['UPwdChg_Info']);
    return $sInfo;
  }

  /** Reset session
   *
   *  Clear the current session and regenerate a new session ID.
   */
  private function resetSession() {
    // Save session locale and login URL
    $sLocale = $this->getCurrentLocale();

    // Clear session and start a new one.
    $_SESSION = array();
    session_regenerate_id(true);

    // Restore session locale and login URL
    $_SESSION['UPwdChg_Locale'] = $sLocale;
  }


  /*
   * METHODS: Authentication
   ********************************************************************************/

  /** Authenticate via user-configured authentication backend
   *
   * @param string $sBack View (ID) to go back to after successful authentication
   * @return array|string User credentials (username, password), Null if no authentication is configured
   */
  private function authenticate($sBack) {
    switch($this->amCONFIG['authentication_method']) {
    case 'http':
      return $this->authenticateHttp();
    case 'ldap':
      return $this->authenticateLdap();
    case 'captcha':
      return $this->authenticateCaptcha($sBack);
    case 'none':
      return array('username' => null, 'password' => null);
    default:
      break;
    }
    trigger_error('['.__METHOD__.'] Invalid authentication method', E_USER_WARNING);
    throw new Exception($this->getText('error:internal_error'));
  }

  /** Authenticate via HTTP
   *
   * @return array|string User credentials (username, password)
   */
  private function authenticateHttp() {
    // Check HTTP authenticated user
    if(!isset($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])) {
      trigger_error('['.__METHOD__.'] HTTP credentials not available', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }

    // End
    return array('username' => $_SERVER['PHP_AUTH_USER'], 'password' => $_SERVER['PHP_AUTH_PW']);
  }

  /** Authenticate via LDAP
   *
   * @return array|string User credentials (username, password)
   */
  private function authenticateLdap() {
    // Retrieve credentials
    if(!isset($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])) {
      header('WWW-Authenticate: Basic');
      header('HTTP/1.0 401 Unauthorized');
      exit;
    }
    $sUsername = $_SERVER['PHP_AUTH_USER'];
    $sPassword = $_SERVER['PHP_AUTH_PW'];

    // Check crendentials
    if(!$this->checkCredentialsLdap($sUsername, $sPassword)) {
      header('WWW-Authenticate: Basic');
      header('HTTP/1.0 401 Unauthorized');
      exit;
    }

    // End
    return array('username' => $sUsername, 'password' => $sPassword);

  }

  /** Authenticate via Captcha
   *
   * @param string $sBack View (ID) to go back to after successful authentication
   * @return array|string Null user credentials (username, password)
   */
  private function authenticateCaptcha($sBack) {
    // Redirection URL
    $sURL = '?view=captcha'.($sBack ? '&back='.$sBack : null);

    // Check captcha
    if(!isset($_SESSION['UPwdChg_Captcha_Challenge'], $_SESSION['UPwdChg_Captcha_Response'], $_SESSION['UPwdChg_Captcha_TTL'])) {
      echo '<SCRIPT TYPE="text/javascript">document.location.replace(\''.$sURL.'\')</SCRIPT>';
      echo '<META HTTP-EQUIV="refresh" CONTENT="1;URL='.$sURL.'" />';
      exit;
    }
    if($_SESSION['UPwdChg_Captcha_Response'] != $_SESSION['UPwdChg_Captcha_Challenge']
       or $_SESSION['UPwdChg_Captcha_TTL'] <= 0) {
      // WTF!?!
      $this->resetSession();
      echo '<SCRIPT TYPE="text/javascript">document.location.replace(\''.$sURL.'\')</SCRIPT>';
      echo '<META HTTP-EQUIV="refresh" CONTENT="1;URL='.$sURL.'" />';
      exit;
    }

    // Decrease Time-to-Live
    $_SESSION['UPwdChg_Captcha_TTL'] -= 1;

    // End
    return array('username' => null, 'password' => null);
  }

  /** Check credentials via user-configured authentication backend
   *
   * @param string $sUsername Username
   * @param string $sPassword Password
   * @param boolean $bUsernameOnly Check only the username (if password is Null)
   * @return boolean True for valid credentials, False otherwise
   */
  private function checkCredentials($sUsername, $sPassword, $bUsernameOnly=false) {
    switch($this->amCONFIG['credentials_check_method']) {
    case 'ldap':
      return $this->checkCredentialsLdap($sUsername, $sPassword, $bUsernameOnly);
    case 'none':
      return true;
    default:
      break;
    }
    trigger_error('['.__METHOD__.'] Invalid password check method', E_USER_WARNING);
    throw new Exception($this->getText('error:internal_error'));
  }

  /** Check credentials via LDAP
   *
   * @param string $sUsername Username
   * @param string $sPassword Password
   * @param boolean $bUsernameOnly Check only the username (if password is Null)
   * @return boolean True for valid credentials, False otherwise
   */
  private function checkCredentialsLdap($sUsername, $sPassword, $bUsernameOnly=false) {
    // Check crendentials
    $hLdap = null;
    try {

      // Authentication

      // ... connect to server
      $hLdap = ldap_connect($this->amCONFIG['ldap_host'],
                            $this->amCONFIG['ldap_port']);
      if($hLdap === false)
        throw new Exception('Failed to connect to LDAP server');

      // ... set protocol version
      if($this->amCONFIG['ldap_protocol_version'] > 0
         and !ldap_set_option($hLdap,
                              LDAP_OPT_PROTOCOL_VERSION,
                              $this->amCONFIG['ldap_protocol_version']))
        throw new Exception('Failed to set LDAP protocol version');

      // ... search for user (?)
      if(empty($this->amCONFIG['ldap_user_dn'])) {
        // ... bind
        if(!empty($this->amCONFIG['ldap_bind_dn'])
           and !ldap_bind($hLdap,
                          $this->amCONFIG['ldap_bind_dn'],
                          $this->amCONFIG['ldap_bind_password']))
          throw new Exception('Failed to bind to LDAP server');

        // ... search
        switch($this->amCONFIG['ldap_user_search_scope']) {
        case 'base': $fLdapSearch = 'ldap_read'; break;
        case 'one': $fLdapSearch = 'ldap_list'; break;
        default: $fLdapSearch = 'ldap_search'; break;
        }
        $hLdapSearch = $fLdapSearch($hLdap,
                                    $this->amCONFIG['ldap_user_base_dn'],
                                    str_ireplace('%{USERNAME}',
                                                 $sUsername,
                                                 $this->amCONFIG['ldap_user_filter']),
                                    array(), 1, 2);
        if($hLdapSearch === false)
          throw new Exception('Failed to perform LDAP user DN search');

        $iCount = ldap_count_entries($hLdap, $hLdapSearch);
        if($iCount == 0)
          throw new Exception('Failed to perform LDAP user DN search; user not found');
        if($iCount > 1)
          throw new Exception('Failed to perform LDAP user DN search; too many match');

        $hEntry = ldap_first_entry($hLdap, $hLdapSearch);
        if($hEntry === false)
          throw new Exception('Failed to retrieve LDAP search result');

        $sBindDn = ldap_get_dn($hLdap, $hEntry);
        if($sBindDn === false)
          throw new Exception('Failed to retrieve LDAP user DN');
        $sBindPassword = $sPassword;

        // ... free resouces
        ldap_free_result($hLdapSearch);
      }
      else {
        $sBindDn = str_ireplace('%{USERNAME}', $sUsername, $this->amCONFIG['ldap_user_dn']);
        $sBindPassword = $sPassword;

        // ... only check username (?)
        if(!isset($sBindPassword) and $bUsernameOnly) {
          $hLdapSearch = ldap_read($hLdap, $sBindDn, '(objectClass=*)', array(), 1, 2);
          if($hLdapSearch === false)
            throw new Exception('Failed to verify LDAP user DN');
          $iCount = ldap_count_entries($hLdap, $hLdapSearch);
          if($iCount == 0)
            throw new Exception('Failed to verify LDAP user DN; user not found');
          if($iCount > 1)
            throw new Exception('Failed to verify LDAP user DN; too many match');
        }
      }

      // ... bind as user
      if(isset($sBindPassword) and !@ldap_bind($hLdap, $sBindDn, $sBindPassword))
        throw new Exception('Failed to bind to LDAP server; user='.$sUsername);

      // ... unbind
      @ldap_unbind($hLdap);

    }
    catch(Exception $e) {
      @ldap_unbind($hLdap);
      trigger_error('['.__METHOD__.'] '.$e->getMessage().'; IP='.$this->sRemoteIP, E_USER_WARNING);
      return false;
    }

    // End
    return true;

  }


  /*
   * METHODS: Password
   ********************************************************************************/

  /** Check the given password characters types
   *
   * @param string $sPassword Password
   * @param string $sCharsetForbidden Forbidden characters
   * @return array|int Types array (lower, upper, digit, punct, other, count)
   */
  private static function getPasswordTypes($sPassword, $sCharsetForbidden) {
    $bForbidden = false;
    $bNotAscii = false;
    $bLower = false;
    $bUpper = false;
    $bDigit = false;
    $bPunct = false;
    $bOther = false;
    $iType = 0;
    foreach(str_split($sPassword) as $sCharacter) {
      if(strpos($sCharsetForbidden, $sCharacter) !== FALSE)
        $bForbidden = true;
      if(ord($sCharacter) < 32 or ord($sCharacter) > 126)
        $bNotAscii = true;
      if(ctype_lower($sCharacter)) {
        if(!$bLower) {
          $bLower = true;
          $iType++;
        }
      }
      elseif(ctype_upper($sCharacter)) {
        if(!$bUpper) {
          $bUpper = true;
          $iType++;
        }
      }
      elseif(ctype_digit($sCharacter)) {
        if(!$bDigit) {
          $bDigit = true;
          $iType++;
        }
      }
      elseif(ctype_punct($sCharacter)) {
        if(!$bPunct) {
          $bPunct = true;
          $iType++;
        }
      }
      else {
        if(!$bOther) {
          $bOther = true;
          $iType++;
        }
      }
    }
    return array('forbidden' => $bForbidden,
                 'notascii' => $bNotAscii,
                 'lower' => $bLower,
                 'upper' => $bUpper,
                 'digit' => $bDigit,
                 'punct' => $bPunct,
                 'other' => $bOther,
                 'count' => $iType);
  }

  /** Check password policy
   *
   * @param string $sPasswordNew New password
   * @param string $sPasswordNew_confirm New password confirmation
   * @param string $sPasswordOld Old password
   */
  private function checkPasswordPolicy($sPasswordNew, $sPasswordNew_confirm, $sPasswordOld=null) {
    $asPasswordErrors = array();

    // Check password confirmation
    if($sPasswordNew != $sPasswordNew_confirm)
      throw new Exception($this->getText('error:password_mismatch'));

    // Check no-change password
    if(isset($sPasswordOld) and $sPasswordNew == $sPasswordOld)
      throw new Exception($this->getText('error:password_identical'));

    // Check minimum length
    if($this->amCONFIG['password_length_minimum']) {
      if(mb_strlen($sPasswordNew) < $this->amCONFIG['password_length_minimum'])
        array_push($asPasswordErrors, $this->getText('error:password_length_minimum'));
    }

    // Check maximum length
    if($this->amCONFIG['password_length_maximum']) {
      if(mb_strlen($sPasswordNew) > $this->amCONFIG['password_length_maximum'])
        array_push($asPasswordErrors, $this->getText('error:password_length_maximum'));
    }

    // Check password characters type
    $aiPasswordTypes = $this->getPasswordTypes($sPasswordNew, $this->amCONFIG['password_charset_forbidden']);
    // ... forbidden
    if($aiPasswordTypes['forbidden'])
      array_push($asPasswordErrors, $this->getText('error:password_charset_forbidden'));
    // ... not ASCII
    if($this->amCONFIG['password_charset_notascii']) {
      if($aiPasswordTypes['notascii'] and $this->amCONFIG['password_charset_notascii']<0)
        array_push($asPasswordErrors, $this->getText('error:password_charset_notascii_forbidden'));
      elseif(!$aiPasswordTypes['notascii'] and $this->amCONFIG['password_charset_notascii']>0)
        array_push($asPasswordErrors, $this->getText('error:password_charset_notascii_required'));
    }
    // ... lowercase
    if($this->amCONFIG['password_type_lower']) {
      if($aiPasswordTypes['lower'] and $this->amCONFIG['password_type_lower']<0)
        array_push($asPasswordErrors, $this->getText('error:password_type_lower_forbidden'));
      elseif(!$aiPasswordTypes['lower'] and $this->amCONFIG['password_type_lower']>0)
        array_push($asPasswordErrors, $this->getText('error:password_type_lower_required'));
    }
    // ... uppercase
    if($this->amCONFIG['password_type_upper']) {
      if($aiPasswordTypes['upper'] and $this->amCONFIG['password_type_upper']<0)
        array_push($asPasswordErrors, $this->getText('error:password_type_upper_forbidden'));
      elseif(!$aiPasswordTypes['upper'] and $this->amCONFIG['password_type_upper']>0)
        array_push($asPasswordErrors, $this->getText('error:password_type_upper_required'));
    }
    // ... digit
    if($this->amCONFIG['password_type_digit']) {
      if($aiPasswordTypes['digit'] and $this->amCONFIG['password_type_digit']<0)
        array_push($asPasswordErrors, $this->getText('error:password_type_digit_forbidden'));
      elseif(!$aiPasswordTypes['digit'] and $this->amCONFIG['password_type_digit']>0)
        array_push($asPasswordErrors, $this->getText('error:password_type_digit_required'));
    }
    // ... punctuation mark
    if($this->amCONFIG['password_type_punct']) {
      if($aiPasswordTypes['punct'] and $this->amCONFIG['password_type_punct']<0)
        array_push($asPasswordErrors, $this->getText('error:password_type_punct_forbidden'));
      elseif(!$aiPasswordTypes['punct'] and $this->amCONFIG['password_type_punct']>0)
        array_push($asPasswordErrors, $this->getText('error:password_type_punct_required'));
    }
    // ... other
    if($this->amCONFIG['password_type_other']) {
      if($aiPasswordTypes['other'] and $this->amCONFIG['password_type_other']<0)
        array_push($asPasswordErrors, $this->getText('error:password_type_other_forbidden'));
      elseif(!$aiPasswordTypes['other'] and $this->amCONFIG['password_type_other']>0)
        array_push($asPasswordErrors, $this->getText('error:password_type_other_required'));
    }
    // ... complexity
    if($this->amCONFIG['password_type_minimum']) {
      if($aiPasswordTypes['count'] < $this->amCONFIG['password_type_minimum'])
        array_push($asPasswordErrors, $this->getText('error:password_type_minimum'));
    }

    // Throw errors
    if(count($asPasswordErrors)) {
      throw new Exception(implode("\n", $asPasswordErrors));
    }
  }

  /** Check password nonce
   *
   * @param string $sUsername Username
   * @param string $sPasswordNonce Password nonce
   */
  private function checkPasswordNonce($sUsername, $sPasswordNonce) {
    // Split nonce ID <-> secret ("<nonce-id>-<nonce-secret>")
    $asPasswordNonce = explode('-', $sPasswordNonce, 2);
    if(count($asPasswordNonce) < 2) {
      throw new Exception($this->getText('error:invalid_password_nonce'));
    }
    $sPasswordNonce_id = $asPasswordNonce[0];
    $sPasswordNonce_secret = $asPasswordNonce[1];

    // Check nonce
    // ... valid characters (NB: prevent path traversal on nonce retrieval)
    if(preg_match('/[[:^alnum:]]/i', $sPasswordNonce_id)) {
      throw new Exception($this->getText('error:invalid_password_nonce'));
    }
    // ... read from file
    $asData = $this->readToken_PasswordNonce($sPasswordNonce_id);
    // ... nonce ID
    if($asData['password-nonce-id'] != $sPasswordNonce_id)
      throw new Exception($this->getText('error:invalid_password_nonce'));
    // ... username
    if($asData['username'] != $sUsername)
      throw new Exception($this->getText('error:invalid_password_nonce'));
    // ... secret
    $sHash_given = base64_decode($asData['password-nonce-secret']['base64']);
    $sHashAlgo = strtolower($asData['password-nonce-secret']['hash']['algorithm']);
    if(substr($sHashAlgo, 0, 7) == 'pbkdf2-') {
      $sHashAlgo_salt = base64_decode($asData['password-nonce-secret']['hash']['salt']['base64']);
      $iHashAlgo_iterations = (integer)$asData['password-nonce-secret']['hash']['iterations'];
      $sHash_compute = hash_pbkdf2(substr($sHashAlgo, 7), $sPasswordNonce_secret, $sHashAlgo_salt, $iHashAlgo_iterations, 0, true);
    } elseif(substr($sHashAlgo, 0, 5) == 'hmac-') {
      $sHashAlgo_salt = base64_decode($asData['password-nonce-secret']['hash']['salt']['base64']);
      $sHash_compute = hash_hmac(substr($sHashAlgo, 5), $sPasswordNonce_secret, $sHashAlgo_salt, true);
    } elseif(substr($sHashAlgo, 0, 5) == 'hash-') {
      $sHash_compute = hash(substr($sHashAlgo, 5), $sPasswordNonce_secret, true);
    } else {
      trigger_error('['.__METHOD__.'] Invalid/unsupported password hash', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }
    if(empty($sHash_given) or empty($sHash_compute) or $sHash_given !== $sHash_compute) {
      throw new Exception($this->getText('error:invalid_password_nonce'));
    }
    // ... expiration
    $asExpiration = date_parse_from_format('Y-m-d\TH:i:s\Z', $asData['expiration']);
    if(!is_array($asExpiration) or $asExpiration['error_count']>0) {
      trigger_error('['.__METHOD__.'] Invalid expiration', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }
    if(time() >= gmmktime($asExpiration['hour'], $asExpiration['minute'], $asExpiration['second'], $asExpiration['month'], $asExpiration['day'], $asExpiration['year'])) {
      throw new Exception($this->getText('error:expired_password_nonce'));
    }
    // ... session
    if($this->amCONFIG['strict_session']) {
      if(!isset($asData['session-id'])) {
        throw new Exception($this->getText('error:internal_error'));
      }
      $sHash_given = base64_decode($asData['session-id']['base64']);
      $sHashAlgo = strtolower($asData['session-id']['hash']['algorithm']);
      if(substr($sHashAlgo, 0, 5) == 'hmac-') {
        $sHashAlgo_salt = base64_decode($asData['session-id']['hash']['salt']['base64']);
        $sHash_compute = hash_hmac(substr($sHashAlgo, 5), session_id(), $sHashAlgo_salt, true);
      } elseif(substr($sHashAlgo, 0, 5) == 'hash-') {
        $sHash_compute = hash(substr($sHashAlgo, 5), session_id(), true);
      } else {
        trigger_error('['.__METHOD__.'] Invalid/unsupported session hash', E_USER_WARNING);
        throw new Exception($this->getText('error:internal_error'));
      }
      if(empty($sHash_given) or empty($sHash_compute) or $sHash_given !== $sHash_compute) {
        throw new Exception($this->getText('error:invalid_session'));
      }
    }
  }


  /*
   * METHODS: Token (shared)
   ********************************************************************************/

  /** Return the normalized token data, for digest purposes
   *
   * @param array|string $asData Token data
   * @return string Normalized token data (string)
   */
  private function getTokenData_Digest($asData) {
    $asData_digest = $asData;
    ksort($asData_digest);
    return implode('|', array_map(function($mValue) { return is_array($mValue) ? $this->getTokenData_Digest($mValue) : $mValue; }, $asData_digest));
  }


  /*
   * METHODS: Token (private)
   ********************************************************************************/

  /** Return the "password-nonce-request" token data (associative array)
   *
   * @param int $iNow Current time (epoch)
   * @param string $sUsername Username
   * @return array|string Token data
   */
  private function getTokenData_PasswordNonceRequest($iNow, $sUsername) {
    // Associative array
    $aTokenData = array(
      'type' => 'password-nonce-request',
      'timestamp' => gmdate('Y-m-d\TH:i:s\Z', $iNow),
      'locale' => $this->getCurrentLocale(),
      'username' => $sUsername,
    );
    if($this->amCONFIG['strict_session']) {
      $aTokenData['session-id'] = session_id();
    }
    return $aTokenData;
  }

  /** Return the "password-change" token data (associative array)
   *
   * @param int $iNow Current time (epoch)
   * @param string $sUsername Username
   * @param string $sPasswordNew New password
   * @param string $sPasswordOld Old password
   * @param string $sPasswordNonce Password nonce
   * @return array|string Token data
   */
  private function getTokenData_PasswordChange($iNow, $sUsername, $sPasswordNew, $sPasswordOld, $sPasswordNonce=null) {
    // Associative array
    $aTokenData = array(
      'type' => 'password-change',
      'timestamp' => gmdate('Y-m-d\TH:i:s\Z', $iNow),
      'locale' => $this->getCurrentLocale(),
      'username' => $sUsername,
      'password-new' => $sPasswordNew,
      'password-old' => $sPasswordOld,
    );
    if($sPasswordNonce) {
      $aTokenData['password-nonce'] = $sPasswordNonce;
      if($this->amCONFIG['strict_session']) {
        $aTokenData['session-id'] = session_id();
      }
    }
    return $aTokenData;
  }

  /** Return the "password-reset" token data (associative array)
   *
   * @param int $iNow Current time (epoch)
   * @param string $sUsername Username
   * @param string $sPasswordNew New password
   * @param string $sPasswordNonce Password nonce
   * @return array|string Token data
   */
  private function getTokenData_PasswordReset($iNow, $sUsername, $sPasswordNew, $sPasswordNonce) {
    // Associative array
    $aTokenData = array(
      'type' => 'password-reset',
      'timestamp' => gmdate('Y-m-d\TH:i:s\Z', $iNow),
      'locale' => $this->getCurrentLocale(),
      'username' => $sUsername,
      'password-new' => $sPasswordNew,
      'password-nonce' => $sPasswordNonce,
    );
    if($this->amCONFIG['strict_session']) {
      $aTokenData['session-id'] = session_id();
    }
    return $aTokenData;
  }

  /** Return the encrypted token
   *
   * @param array|string $asData Token data
   * @return string Token
   */
  private function encryptToken($asData) {
    // Compute the data digest
    $sDataDigest = hash(UPwdChg::DIGEST_ALGO, mb_convert_encoding($this->getTokenData_Digest($asData), 'utf-8'), true);
    if(empty($sDataDigest)) {
      trigger_error('['.__METHOD__.'] Failed to compute data digest', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }
    $asData['digest'] = array(
      'algorithm' => UPwdChg::DIGEST_ALGO,
      'base64' => base64_encode($sDataDigest),
    );

    // Encode the data (JSON)
    $sData = json_encode($asData, JSON_PRETTY_PRINT);

    // Encrypt the (symmetric) data key
    $sDataKey = mcrypt_create_iv(UPwdChg::CIPHER_KEY_LENGTH, $this->amCONFIG['random_source']);
    // ... load the RSA public key
    $sPublicKey = file_get_contents($this->amCONFIG['public_key_file']);
    if(empty($sPublicKey)) {
      trigger_error('['.__METHOD__.'] Failed to load RSA public key', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }
    $mPublicKey = openssl_pkey_get_public($sPublicKey);
    if($mPublicKey === false) {
      trigger_error('['.__METHOD__.'] Invalid RSA public key', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }
    // ... encrypt the data key using the RSA public key
    if(openssl_public_encrypt($sDataKey, $sDataKeyEncrypted, $mPublicKey, OPENSSL_PKCS1_OAEP_PADDING) === false) {
      trigger_error('['.__METHOD__.'] Failed to encrypt data key', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }

    // Encrypt the data
    $sDataIv = mcrypt_create_iv(UPwdChg::CIPHER_IV_LENGTH, $this->amCONFIG['random_source']);
    $sDataEncrypted = openssl_encrypt($sData, UPwdChg::CIPHER_ALGO, $sDataKey, true, $sDataIv);
    if(empty($sDataEncrypted)) {
      trigger_error('['.__METHOD__.'] Failed to encrypt data', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }

    // Encode the token (JSON)
    return json_encode(
      array(
        'type' => 'application/x.upwdchg-token+json',
        'data' => array(
          'cipher' => array(
            'algorithm' => UPwdChg::CIPHER_ALGO,
            'iv' => array(
              'base64' => base64_encode($sDataIv),
            ),
            'key' => array(
              'cipher' => array(
                'algorithm' => 'public',
              ),
              'base64' => base64_encode($sDataKeyEncrypted),
            ),
          ),
          'base64' => base64_encode($sDataEncrypted),
        ),
      ),
      JSON_PRETTY_PRINT
    );
  }

  /** Write the given token to file
   *
   * @param int $iNow Current time (epoch)
   * @param string $sToken Token
   */
  private function writeToken($iNow, $sToken) {
    // Write the token to storage
    $sFile = $this->amCONFIG['tokens_directory_private'].DIRECTORY_SEPARATOR.gmdate('Ymd\THis\Z-', $iNow).bin2hex(openssl_random_pseudo_bytes(8)).'.token';
    $iUMask_old = umask();
    umask(0137);
    if(file_put_contents($sFile, $sToken) != strlen($sToken)) {
      umask($iUMask_old);
      trigger_error('['.__METHOD__.'] Failed to write token to file', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }
    umask($iUMask_old);
  }

  /** Write the encrypted "password-nonce-request" token to file
   *
   * @param string $sUsername Username
   */
  private function writeToken_PasswordNonceRequest($sUsername) {
    $iNow = time();
    $asData = $this->getTokenData_PasswordNonceRequest($iNow, $sUsername);
    $sToken = $this->encryptToken($asData);
    $this->writeToken($iNow, $sToken);
  }

  /** Write the encrypted "password-change" token to file
   *
   * @param string $sUsername Username
   * @param string $sPasswordNew New password
   * @param string $sPasswordOld Old password
   * @param string $sPasswordNonce Password nonce
   */
  private function writeToken_PasswordChange($sUsername, $sPasswordNew, $sPasswordOld, $sPasswordNonce=null) {
    $iNow = time();
    $asData = $this->getTokenData_PasswordChange($iNow, $sUsername, $sPasswordNew, $sPasswordOld, $sPasswordNonce);
    $sToken = $this->encryptToken($asData);
    $this->writeToken($iNow, $sToken);
  }

  /** Write the encrypted "password-reset" token to file
   *
   * @param string $sUsername Username
   * @param string $sPasswordNew New password
   * @param string $sPasswordNonce Password nonce
   */
  private function writeToken_PasswordReset($sUsername, $sPasswordNew, $sPasswordNonce) {
    $iNow = time();
    $asData = $this->getTokenData_PasswordReset($iNow, $sUsername, $sPasswordNew, $sPasswordNonce);
    $sToken = $this->encryptToken($asData);
    $this->writeToken($iNow, $sToken);
  }


  /*
   * METHODS: Token (public)
   ********************************************************************************/

  /** Return the decrypted token data
   *
   * @param array|string $asToken Token
   * @return array|string Token data
   */
  private function decryptToken($asToken) {
    // Decode the data (Base64)
    $sData = base64_decode($asToken['data']['base64']);
    if(empty($sData)) {
      trigger_error('['.__METHOD__.'] Failed to decode token data', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }

    // Decrypt the (symmetric) data key
    $sDataKey = base64_decode($asToken['data']['cipher']['key']['base64']);
    if(empty($sDataKey)) {
      trigger_error('['.__METHOD__.'] Failed to decode data key', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }
    $sDataKeyCipherAlgo = strtolower($asToken['data']['cipher']['key']['cipher']['algorithm']);
    switch($sDataKeyCipherAlgo) {
    case 'private':
      // ... load the RSA public key
      $sPublicKey = file_get_contents($this->amCONFIG['public_key_file']);
      if(empty($sPublicKey)) {
        trigger_error('['.__METHOD__.'] Failed to load RSA public key', E_USER_WARNING);
        throw new Exception($this->getText('error:internal_error'));
      }
      $mPublicKey = openssl_pkey_get_public($sPublicKey);
      if($mPublicKey === false) {
        trigger_error('['.__METHOD__.'] Invalid RSA public key', E_USER_WARNING);
        throw new Exception($this->getText('error:internal_error'));
      }
      // ... decrypt the data key using the RSA public key
      if(openssl_public_decrypt($sDataKey, $sDataKeyDecrypted, $mPublicKey, OPENSSL_PKCS1_PADDING) === false) {
        trigger_error('['.__METHOD__.'] Failed to decrypt data key', E_USER_WARNING);
        throw new Exception($this->getText('error:internal_error'));
      }
      break;
    default:
      trigger_error('['.__METHOD__.'] Invalid/unsupported data key cipher', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }

    // Decrypt the data
    $sDataCipherAlgo = str_replace('_', '-', strtolower($asToken['data']['cipher']['algorithm']));
    $sDataIv = base64_decode($asToken['data']['cipher']['iv']['base64']);
    switch($sDataCipherAlgo) {
    case 'aes-256-cbc':
    case 'aes-192-cbc':
    case 'aes-128-cbc':
    case 'bf-cbc':
      $sData = openssl_decrypt($sData, $sDataCipherAlgo, $sDataKeyDecrypted, OPENSSL_RAW_DATA, $sDataIv);
      if(empty($sData)) {
        trigger_error('['.__METHOD__.'] Failed to decrypt data', E_USER_WARNING);
        throw new Exception($this->getText('error:internal_error'));
      }
      break;
    default:
      trigger_error('['.__METHOD__.'] Invalid/unsupported data cipher', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }

    // Decode the data (JSON)
    $asData = json_decode($sData, true);
    if(is_null($asData)) {
      trigger_error('['.__METHOD__.'] Failed to parse data', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }
    if(!isset($asData['type'])) {
      trigger_error('['.__METHOD__.'] Invalid data', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }

    // Check the data digest
    $sDataDigestAlgo = strtolower($asData['digest']['algorithm']);
    $sDataDigest_given = base64_decode($asData['digest']['base64']);
    switch($sDataDigestAlgo) {
    case 'sha512':
    case 'sha384':
    case 'sha256':
    case 'sha224':
    case 'sha1':
    case 'md5':
      $asData_digest = array_filter($asData, function($sKey) { return $sKey!='digest'; }, ARRAY_FILTER_USE_KEY);
      $sDataDigest_compute = hash($sDataDigestAlgo, mb_convert_encoding($this->getTokenData_Digest($asData_digest), 'utf-8'), true);
      break;
    default:
      trigger_error('['.__METHOD__.'] Invalid/unsupported data digest', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }
    if(empty($sDataDigest_given) or empty($sDataDigest_compute) or $sDataDigest_given !== $sDataDigest_compute) {
      trigger_error('['.__METHOD__.'] Invalid digest', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }

    // Data
    return $asData;
  }

  /** Read the token (associative array) from the given file
   *
   * @param string $sFile File (path)
   * @return array|string Token
   */
  private function readToken($sFile) {
    // Read token from storage
    if(!is_readable($sFile)) {
      trigger_error('['.__METHOD__.'] Missing/unreadable file', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }
    $asToken = json_decode(file_get_contents($sFile), true);
    if(is_null($asToken)) {
      trigger_error('['.__METHOD__.'] Failed to parse token file', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }
    if(!isset($asToken['type'])) {
      trigger_error('['.__METHOD__.'] Invalid token', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }
    if($asToken['type'] != 'application/x.upwdchg-token+json') {
      trigger_error('['.__METHOD__.'] Invalid token type', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }
    return $asToken;
  }

  /** Read the "password-nonce" token (associative array) from the file corresponding to the given ID
   *
   * @param string $sPasswordNonce_id Password nonce ID
   * @return array|string Token data
   */
  private function readToken_PasswordNonce($sPasswordNonce_id) {
    // Read password nonce from storage
    $sFile = $this->amCONFIG['tokens_directory_public'].DIRECTORY_SEPARATOR.$sPasswordNonce_id.'.nonce';
    if(!is_readable($sFile)) {
      throw new Exception($this->getText('error:invalid_password_nonce'));
    }
    $asToken = $this->readToken($sFile);
    $asData = $this->decryptToken($asToken);
    if(
      !isset($asData['type'], $asData['timestamp'], $asData['expiration'], $asData['username'], $asData['password-nonce-id'], $asData['password-nonce-secret'])
      or $asData['type'] != 'password-nonce'
    ) {
      trigger_error('['.__METHOD__.'] Invalid password nonce', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }
    return $asData;
  }


  /*
   * METHODS: HTML
   ********************************************************************************/

  /** HTML page controller (Model/View Controller)
   *
   * <P><B>SYNOPSIS:</B> This function invokes the controller implementing the logic
   * for the password change request and returns the HTML view that must displayed as
   * result. See the sample <SAMP>index.php</SAMP> file for usage example.</P>
   *
   * @return string View ID (to display)
   */
  public function controlPage() {
    // Controller
    $amFormData = array();
    try {
      // Check encryption
      if($this->amCONFIG['force_ssl'] and !isset($_SERVER['HTTPS'])) {
        throw new Exception($this->getText('error:unsecure_channel'));
      }

      // Request
      // ... view
      $sView = null;
      if(isset($_GET['view'])) {
        if(!is_scalar($_GET['view']) or strlen($_GET['view']) > UPwdChg::INPUT_MAX_LENGTH or preg_match('/[^a-z-]/', $_GET['view'])) {
          trigger_error('['.__METHOD__.'] Invalid view request; IP='.$this->sRemoteIP, E_USER_WARNING);
          throw new Exception($this->getText('error:internal_error'));
        }
        $sView = trim($_GET['view']);
      }
      // ... back
      $sBack = null;
      if(isset($_GET['back'])) {
        if(!is_scalar($_GET['back']) or strlen($_GET['back']) > UPwdChg::INPUT_MAX_LENGTH or preg_match('/[^a-z-]/', $_GET['back'])) {
          trigger_error('['.__METHOD__.'] Invalid back request; IP='.$this->sRemoteIP, E_USER_WARNING);
          throw new Exception($this->getText('error:internal_error'));
        }
        $sBack = trim($_GET['back']);
      }
      // ... action
      $sDo = null;
      if(isset($_POST['do'])) {
        if(!is_scalar($_POST['do']) or strlen($_POST['do']) > UPwdChg::INPUT_MAX_LENGTH or preg_match('/[^a-z-]/', $_POST['do'])) {
          trigger_error('['.__METHOD__.'] Invalid form data (request:action); IP='.$this->sRemoteIP, E_USER_WARNING);
          throw new Exception($this->getText('error:invalid_form_data'));
        }
        $sDo = trim($_POST['do']);
      }

      // Default view (make URI/request explicit)
      if(empty($sDo) and empty($sView)) {
        if($this->amCONFIG['password_nonce'] and !$this->amCONFIG['password_reset'])
          // ... two-factor password change; we need a nonce first
          $sView = 'password-nonce-request';
        else
          $sView = 'password-change';
        echo '<SCRIPT TYPE="text/javascript">document.location.replace(\'?view='.$sView.'\')</SCRIPT>';
        echo '<META HTTP-EQUIV="refresh" CONTENT="1;URL=?view='.$sView.'" />';
        exit;
      }

      // PRE-AUTHENTICATION

      // Actions
      switch($sDo) {

      case 'reset':
        // Clear session
        $this->resetSession();

        // Redirect (prevent form resubmission)
        echo '<SCRIPT TYPE="text/javascript">document.location.replace(\'?\')</SCRIPT>';
        echo '<META HTTP-EQUIV="refresh" CONTENT="1;URL=?" />';
        exit;

      case 'locale':
        // Retrieve form variables
        if(!isset($_POST['locale'])
           or !is_scalar($_POST['locale']) or strlen($_POST['locale']) > UPwdChg::INPUT_MAX_LENGTH) {
          trigger_error('['.__METHOD__.'] Invalid form data (request:arguments); IP='.$this->sRemoteIP, E_USER_WARNING);
          throw new Exception($this->getText('error:invalid_form_data'));
        }
        $sLocale = trim($_POST['locale']);

        // Check and set locale
        if(!in_array($sLocale, $this->getSupportedLocales())) {
          trigger_error('['.__METHOD__.'] Invalid locale; IP='.$this->sRemoteIP, E_USER_WARNING);
          throw new Exception($this->getText('error:invalid_form_data'));
        }
        $_SESSION['UPwdChg_Locale'] = $sLocale;

        // Redirect (make URI/request explicit)
        echo '<SCRIPT TYPE="text/javascript">document.location.replace(\'?\')</SCRIPT>';
        echo '<META HTTP-EQUIV="refresh" CONTENT="1;URL=?" />';
        exit;

      }

      // Views
      if(empty($sDo)) {
        switch($sView) {

        case 'captcha':
          if($this->amCONFIG['authentication_method'] != 'captcha') {
            trigger_error('['.__METHOD__.'] Invalid view request (captcha); IP='.$this->sRemoteIP, E_USER_WARNING);
            throw new Exception($this->getText('error:internal_error'));
          }
          $this->amFORMDATA = array('VIEW' => $sView);
          return $this->amFORMDATA['VIEW'];

        case 'captcha-challenge':
          if($this->amCONFIG['authentication_method'] != 'captcha') {
            trigger_error('['.__METHOD__.'] Invalid view request (captcha-challenge); IP='.$this->sRemoteIP, E_USER_WARNING);
            throw new Exception($this->getText('error:internal_error'));
          }
          $this->outputCaptcha();
          exit;

        case 'password-change-confirm':
          $this->amFORMDATA = array('VIEW' => $sView);
          return $this->amFORMDATA['VIEW'];

        case 'password-reset-confirm':
          if(!$this->amCONFIG['password_nonce'] or !$this->amCONFIG['password_reset']) {
            trigger_error('['.__METHOD__.'] Invalid view request (password-reset-confirm); IP='.$this->sRemoteIP, E_USER_WARNING);
            throw new Exception($this->getText('error:internal_error'));
          }
          $this->amFORMDATA = array('VIEW' => $sView);
          return $this->amFORMDATA['VIEW'];

        }
      }

      // AUTHENTICATION
      $sUsername = null;
      $sPasswordNonce = null;
      $sPasswordOld = null;
      $sPasswordNew = null;

      // Actions
      switch($sDo) {

      case 'captcha':
        if($this->amCONFIG['authentication_method'] != 'captcha') {
          trigger_error('['.__METHOD__.'] Invalid action request (captcha); IP='.$this->sRemoteIP, E_USER_WARNING);
          throw new Exception($this->getText('error:internal_error'));
        }
        $sView = 'captcha';

        // Retrieve form variables
        if(!isset($_POST['captcha'])
           or !is_scalar($_POST['captcha']) or strlen($_POST['captcha']) > UPwdChg::INPUT_MAX_LENGTH) {
          trigger_error('['.__METHOD__.'] Invalid form data (request:arguments); IP='.$this->sRemoteIP, E_USER_WARNING);
          throw new Exception($this->getText('error:invalid_form_data'));
        }
        $sCaptcha = trim($_POST['captcha']);

        // Check captcha
        if(!isset($_SESSION['UPwdChg_Captcha_Challenge']) or $sCaptcha != $_SESSION['UPwdChg_Captcha_Challenge']) {
          throw new Exception($this->getText('error:invalid_captcha'));
        }
        $_SESSION['UPwdChg_Captcha_Response'] = $sCaptcha;
        $_SESSION['UPwdChg_Captcha_TTL'] = $this->amCONFIG['captcha_ttl'];

        // Redirect (prevent form resubmission)
        echo '<SCRIPT TYPE="text/javascript">document.location.replace(\'?'.($sBack ? 'view='.$sBack : null).'\')</SCRIPT>';
        echo '<META HTTP-EQUIV="refresh" CONTENT="1;URL=?'.($sBack ? 'view='.$sBack : null).'" />';
        exit;

      }

      // ... authenticate
      if($this->amCONFIG['authentication_method'] != 'none') {
        // WARNING: let's be overly cautious on those 'authentication_exempt' tests!
        if(!empty($sDo) and in_array($sDo, $this->amCONFIG['authentication_exempt'], true)) {
          assert(true);
        }
        elseif(empty($sDo) and !empty($sView) and in_array($sView, $this->amCONFIG['authentication_exempt'], true)) {
          assert(true);
        }
        else {
          $asCredentials = $this->authenticate($sView);
          $sUsername = $amFormData['username'] = $asCredentials['username'];
          $sPasswordOld = $asCredentials['password'];
        }
      }

      // POST-AUTHENTICATION

      // Actions
      switch($sDo) {

      case 'password-nonce-request':
        if(!$this->amCONFIG['password_nonce']) {
          trigger_error('['.__METHOD__.'] Invalid action request (password-nonce-request); IP='.$this->sRemoteIP, E_USER_WARNING);
          throw new Exception($this->getText('error:internal_error'));
        }
        $sView = 'password-nonce-request';

        // Retrieve arguments
        if(!isset($_POST['username'])
           or !is_scalar($_POST['username']) or strlen($_POST['username']) > UPwdChg::INPUT_MAX_LENGTH) {
          trigger_error('['.__METHOD__.'] Invalid form data (request:arguments); IP='.$this->sRemoteIP, E_USER_WARNING);
          throw new Exception($this->getText('error:invalid_form_data'));
        }

        // Credentials
        if(in_array($this->amCONFIG['authentication_method'], array('none', 'captcha'))) {
          $sUsername = $amFormData['username'] = $_POST['username'];
        }

        // Check credentials (username only)
        if($this->amCONFIG['credentials_check_method'] != 'none') {
          if(!$this->checkCredentials($sUsername, null, true))
            throw new Exception($this->getText('error:invalid_credentials'));
        }

        // Write token
        $this->writeToken_PasswordNonceRequest($sUsername);

        // User feedback
        $this->infoAdd($this->getText('info:password_nonce_request'));

        // Redirect (prevent form resubmission)
        if(!$this->amCONFIG['password_reset']) {
          echo '<SCRIPT TYPE="text/javascript">document.location.replace(\'?view=password-change\')</SCRIPT>';
          echo '<META HTTP-EQUIV="refresh" CONTENT="1;URL=?view=password-change" />';
        }
        else {
          echo '<SCRIPT TYPE="text/javascript">document.location.replace(\'?view=password-reset\')</SCRIPT>';
          echo '<META HTTP-EQUIV="refresh" CONTENT="1;URL=?view=password-reset" />';
        }
        exit;

      case 'password-change':
        $sView = 'password-change';

        // Retrieve arguments
        if(!isset($_POST['username'], $_POST['password_nonce'], $_POST['password_old'], $_POST['password_new'], $_POST['password_confirm'])
           or !is_scalar($_POST['username']) or strlen($_POST['username']) > UPwdChg::INPUT_MAX_LENGTH
           or !is_scalar($_POST['password_nonce']) or strlen($_POST['password_nonce']) > UPwdChg::INPUT_MAX_LENGTH
           or !is_scalar($_POST['password_old']) or strlen($_POST['password_old']) > UPwdChg::INPUT_MAX_LENGTH
           or !is_scalar($_POST['password_new']) or strlen($_POST['password_new']) > UPwdChg::INPUT_MAX_LENGTH
           or !is_scalar($_POST['password_confirm']) or strlen($_POST['password_confirm']) > UPwdChg::INPUT_MAX_LENGTH) {
          trigger_error('['.__METHOD__.'] Invalid form data (request:arguments); IP='.$this->sRemoteIP, E_USER_WARNING);
          throw new Exception($this->getText('error:invalid_form_data'));
        }

        // Credentials
        if(in_array($this->amCONFIG['authentication_method'], array('none', 'captcha'))) {
          $sUsername = $amFormData['username'] = $_POST['username'];
          $sPasswordOld = $_POST['password_old'];
        }
        if($this->amCONFIG['password_nonce'] and !$this->amCONFIG['password_reset']) {
          $sPasswordNonce = $_POST['password_nonce'];
        }
        if($this->amCONFIG['credentials_check_method'] != 'none') {
          $sPasswordOld = $_POST['password_old'];
        }
        $sPasswordNew = $_POST['password_new'];
        $sPasswordNew_confirm = $_POST['password_confirm'];

        // Check credentials
        if($this->amCONFIG['credentials_check_method'] != 'none') {
          if(!$this->checkCredentials($sUsername, $sPasswordOld))
            throw new Exception($this->getText('error:invalid_credentials'));
        }

        // Check password nonce (two-factor password change)
        if(isset($sPasswordNonce)) {
          $this->checkPasswordNonce($sUsername, $sPasswordNonce);
        }

        // Check password policy
        $this->checkPasswordPolicy($sPasswordNew, $sPasswordNew_confirm, $sPasswordOld);

        // Write token
        $this->writeToken_PasswordChange($sUsername, $sPasswordNew, $sPasswordOld, $sPasswordNonce);

        // Clear session (prevent replay of current session)
        $this->resetSession();

        // Redirect (prevent form resubmission)
        echo '<SCRIPT TYPE="text/javascript">document.location.replace(\'?view=password-change-confirm\')</SCRIPT>';
        echo '<META HTTP-EQUIV="refresh" CONTENT="1;URL=?view=password-change-confirm" />';
        exit;

      case 'password-reset':
        if(!$this->amCONFIG['password_nonce'] or !$this->amCONFIG['password_reset']) {
          trigger_error('['.__METHOD__.'] Invalid action request (password-reset); IP='.$this->sRemoteIP, E_USER_WARNING);
          throw new Exception($this->getText('error:internal_error'));
        }
        $sView = 'password-reset';

        // Retrieve arguments
        if(!isset($_POST['username'], $_POST['password_nonce'], $_POST['password_new'], $_POST['password_confirm'])
           or !is_scalar($_POST['username']) or strlen($_POST['username']) > UPwdChg::INPUT_MAX_LENGTH
           or !is_scalar($_POST['password_nonce']) or strlen($_POST['password_nonce']) > UPwdChg::INPUT_MAX_LENGTH
           or !is_scalar($_POST['password_new']) or strlen($_POST['password_new']) > UPwdChg::INPUT_MAX_LENGTH
           or !is_scalar($_POST['password_confirm']) or strlen($_POST['password_confirm']) > UPwdChg::INPUT_MAX_LENGTH) {
          trigger_error('['.__METHOD__.'] Invalid form data (request:arguments); IP='.$this->sRemoteIP, E_USER_WARNING);
          throw new Exception($this->getText('error:invalid_form_data'));
        }

        // Credentials
        $sUsername = $amFormData['username'] = $_POST['username'];
        $sPasswordNonce = $_POST['password_nonce'];
        $sPasswordNew = $_POST['password_new'];
        $sPasswordNew_confirm = $_POST['password_confirm'];

        // Check credentials (username only)
        if($this->amCONFIG['credentials_check_method'] != 'none') {
          if(!$this->checkCredentials($sUsername, null, false))
            throw new Exception($this->getText('error:invalid_credentials'));
        }

        // Check password nonce
        $this->checkPasswordNonce($sUsername, $sPasswordNonce);

        // Check password policy
        $this->checkPasswordPolicy($sPasswordNew, $sPasswordNew_confirm);

        // Write token
        $this->writeToken_PasswordReset($sUsername, $sPasswordNew, $sPasswordNonce);

        // Clear session (prevent replay of current session)
        $this->resetSession();

        // Redirect (prevent form resubmission)
        echo '<SCRIPT TYPE="text/javascript">document.location.replace(\'?view=password-reset-confirm\')</SCRIPT>';
        echo '<META HTTP-EQUIV="refresh" CONTENT="1;URL=?view=password-reset-confirm" />';
        exit;

      default:
        // Nothing to do here
        break;

      }

    }
    catch(Exception $e) {
      // Save the error message
      $this->errorAdd($e->getMessage());
    }

    // Save form data
    $this->amFORMDATA = array_merge(array('VIEW' => $sView, 'ERROR' => $this->errorGet(), 'INFO' => $this->infoGet()), $amFormData);

    // Done
    return $this->amFORMDATA['VIEW'];
  }

  /** Retrieve data (variable value) from the controller
   *
   * @param string $sID Data (variable) ID
   * @return mixed Data (variable) value
   */
  public function getFormData($sID) {
    return isset($this->amFORMDATA[$sID]) ? $this->amFORMDATA[$sID] : null;
  }

  /** Retrieve the form's HTML code from the controller (for the given view)
   *
   * @param string $sID Form ID
   * @return string Form's HTML code
   */
  public function getFormHtml($sID) {
    // Request
    // ... back
    $sBack = null;
    if(isset($_GET['back']) and is_scalar($_GET['back']) and strlen($_GET['back']) <= UPwdChg::INPUT_MAX_LENGTH and !preg_match('/[^a-z-]/', $_GET['back'])) {
      $sBack = trim($_GET['back']);
    }

    // Build form
    $sHTML = '';
    switch($sID) {

    case 'reset':
      $sHTML .= '<FORM ID="UPwdChg_reset" METHOD="post" ACTION="'.$_SERVER['SCRIPT_NAME'].'">';
      $sHTML .= '<INPUT TYPE="hidden" NAME="do" VALUE="reset" />';
      $sHTML .= '<TABLE CELLSPACING="0">';
      $sHTML .= '<TR><TD CLASS="link" COLSPAN="2"><A HREF="javascript:;" ONCLICK="javascript:document.getElementById(\'UPwdChg_reset\').submit();">'.htmlentities($this->getText('label:reset')).'</A></TD></TR>';
      $sHTML .= '</TABLE>';
      $sHTML .= '</FORM>';
      break;

    case 'locale':
      $sCurrentLocale = $this->getCurrentLocale();

      // ... HTML
      $sHTML .= '<FORM ID="UPwdChg_locale" METHOD="post" ACTION="'.$_SERVER['SCRIPT_NAME'].'">';
      $sHTML .= '<INPUT TYPE="hidden" NAME="do" VALUE="locale" />';
      $sHTML .= '<TABLE CELLSPACING="0"><TR>';
      $sHTML .= '<TD CLASS="label">'.htmlentities($this->getText('label:language')).':</TD>';
      $sHTML .= '<TD CLASS="input"><SELECT NAME="locale" ONCHANGE="javascript:document.getElementById(\'UPwdChg_locale\').submit();" STYLE="WIDTH:50px;">';
      foreach($this->getSupportedLocales() as $sLocale) {
        $sHTML .= '<OPTION VALUE="'.$sLocale.'"'.($sLocale == $sCurrentLocale ? ' SELECTED' : null).'>'.$sLocale.'</OPTION>';
      }
      $sHTML .= '</SELECT></TD>';
      $sHTML .= '</TR></TABLE>';
      $sHTML .= '</FORM>';
      break;

    case 'captcha':
      if($this->amCONFIG['authentication_method'] != 'captcha') {
        trigger_error('['.__METHOD__.'] Invalid view request (captcha); IP='.$this->sRemoteIP, E_USER_WARNING);
        throw new Exception($this->getText('error:internal_error'));
      }

      // ... HTML
      $sHTML .= '<FORM ID="UPwdChg_form" METHOD="post" ACTION="'.$_SERVER['SCRIPT_NAME'].'?view=captcha'.($sBack ? '&back='.$sBack : null).'">';
      $sHTML .= '<INPUT TYPE="hidden" NAME="do" VALUE="captcha" />';
      $sHTML .= '<TABLE CELLSPACING="0"><TR>';
      $iTabIndex = 1;

      // ... captcha (response)
      $sHTML .= '<TR><TD CLASS="label">'.htmlentities($this->getText('label:captcha')).'&nbsp;(<A HREF="?view=captcha'.($sBack ? '&back='.$sBack : null).'">&#x21bb;</A>):</TD><TD CLASS="input"><SPAN CLASS="required"><INPUT TYPE="text" NAME="captcha" TABINDEX="'.$iTabIndex++.'" /></SPAN></TD></TR>';

      // ... captcha (challenge)
      $sHTML .= '<TR><TD CLASS="label">&nbsp;</TD><TD CLASS="input"><IMG ALT="Captcha" SRC="?view=captcha-challenge" WIDTH="'.$this->amCONFIG['captcha_width'].'" HEIGHT="'.$this->amCONFIG['captcha_height'].'" /></TD><TD CLASS="note">&nbsp;</TD></TR>';

      // ... submit
      $sHTML .= '<TR><TD CLASS="button" COLSPAN="2"><BUTTON TYPE="submit" TABINDEX="'.$iTabIndex.'">'.htmlentities($this->getText('label:submit')).'</BUTTON></TD></TR>';
      $sHTML .= '</TR></TABLE>';
      $sHTML .= '</FORM>';
      break;

    case 'password-policy':
      // ... HTML
      $sHTML .= '<UL>';
      if($this->amCONFIG['password_length_minimum'])
        $sHTML .= '<LI>'.htmlentities($this->getText('error:password_length_minimum')).'</LI>';
      if($this->amCONFIG['password_length_maximum'])
        $sHTML .= '<LI>'.htmlentities($this->getText('error:password_length_maximum')).'</LI>';
      if(!empty($this->amCONFIG['password_charset_forbidden']))
        $sHTML .= '<LI>'.htmlentities($this->getText('info:password_charset_forbidden')).'</LI>';
      if($this->amCONFIG['password_charset_notascii']<0)
        $sHTML .= '<LI>'.htmlentities($this->getText('error:password_charset_notascii_forbidden')).'</LI>';
      elseif($this->amCONFIG['password_charset_notascii']>0)
        $sHTML .= '<LI>'.htmlentities($this->getText('error:password_charset_notascii_required')).'</LI>';
      else
        $sHTML .= '<LI>'.htmlentities($this->getText('info:password_charset_notascii')).'</LI>';
      if($this->amCONFIG['password_type_lower']<0)
        $sHTML .= '<LI>'.htmlentities($this->getText('error:password_type_lower_forbidden')).'</LI>';
      elseif($this->amCONFIG['password_type_lower']>0)
        $sHTML .= '<LI>'.htmlentities($this->getText('error:password_type_lower_required')).'</LI>';
      else
        $sHTML .= '<LI>'.htmlentities($this->getText('info:password_type_lower')).'</LI>';
      if($this->amCONFIG['password_type_upper']<0)
        $sHTML .= '<LI>'.htmlentities($this->getText('error:password_type_upper_forbidden')).'</LI>';
      elseif($this->amCONFIG['password_type_upper']>0)
        $sHTML .= '<LI>'.htmlentities($this->getText('error:password_type_upper_required')).'</LI>';
      else
        $sHTML .= '<LI>'.htmlentities($this->getText('info:password_type_upper')).'</LI>';
      if($this->amCONFIG['password_type_digit']<0)
        $sHTML .= '<LI>'.htmlentities($this->getText('error:password_type_digit_forbidden')).'</LI>';
      elseif($this->amCONFIG['password_type_digit']>0)
        $sHTML .= '<LI>'.htmlentities($this->getText('error:password_type_digit_required')).'</LI>';
      else
        $sHTML .= '<LI>'.htmlentities($this->getText('info:password_type_digit')).'</LI>';
      if($this->amCONFIG['password_type_punct']<0)
        $sHTML .= '<LI>'.htmlentities($this->getText('error:password_type_punct_forbidden')).'</LI>';
      elseif($this->amCONFIG['password_type_punct']>0)
        $sHTML .= '<LI>'.htmlentities($this->getText('error:password_type_punct_required')).'</LI>';
      else
        $sHTML .= '<LI>'.htmlentities($this->getText('info:password_type_punct')).'</LI>';
      if($this->amCONFIG['password_type_other']<0)
        $sHTML .= '<LI>'.htmlentities($this->getText('error:password_type_other_forbidden')).'</LI>';
      elseif($this->amCONFIG['password_type_other']>0)
        $sHTML .= '<LI>'.htmlentities($this->getText('error:password_type_other_required')).'</LI>';
      else
        $sHTML .= '<LI>'.htmlentities($this->getText('info:password_type_other')).'</LI>';
      if($this->amCONFIG['password_type_minimum'])
        $sHTML .= '<LI>'.htmlentities($this->getText('error:password_type_minimum')).'</LI>';
      $sHTML .= '</UL>';
      $sHTML .= '<P CLASS="link"><A HREF="?'.($sBack ? 'view='.$sBack : null).'">'.htmlentities($this->getText('label:password_policy_back')).'</A></P>';
      break;

    case 'password-nonce-request':
      if(!$this->amCONFIG['password_nonce']) {
        trigger_error('['.__METHOD__.'] Invalid view request (password-nonce-request); IP='.$this->sRemoteIP, E_USER_WARNING);
        throw new Exception($this->getText('error:internal_error'));
      }

      // ... configuration-dependent fields
      $bFormUsername = false;
      if(in_array($this->amCONFIG['authentication_method'], array('none', 'captcha'))) {
        $bFormUsername = true;
      }

      // ... HTML
      $sHTML .= '<FORM ID="UPwdChg_form" METHOD="post" ACTION="'.$_SERVER['SCRIPT_NAME'].'?view=password-nonce-request">';
      $sHTML .= '<INPUT TYPE="hidden" NAME="do" VALUE="password-nonce-request" />';
      $sHTML .= '<TABLE CELLSPACING="0">';
      $iTabIndex = 1;

      // ... username
      if($bFormUsername)
        $sHTML .= '<TR><TD CLASS="label">'.htmlentities($this->getText('label:username')).':</TD><TD CLASS="input"><SPAN CLASS="required"><INPUT TYPE="text" NAME="username" TABINDEX="'.$iTabIndex++.'" VALUE="'.htmlentities($this->getFormData('username')).'" /></SPAN></TD></TR>';
      else
        $sHTML .= '<TR><TD CLASS="label">'.htmlentities($this->getText('label:username')).':</TD><TD CLASS="input"><SPAN CLASS="readonly"><INPUT TYPE="text" NAME="username" VALUE="'.htmlentities($this->getFormData('username')).'" READONLY="1" /></SPAN></TD></TR>';

      // ... submit
      $sHTML .= '<TR><TD CLASS="button" COLSPAN="2"><BUTTON TYPE="submit" TABINDEX="'.$iTabIndex.'">'.htmlentities($this->getText('label:submit')).'</BUTTON></TD></TR>';
      $sHTML .= '</TABLE>';
      $sHTML .= '</FORM>';
      break;

    case 'password-change':
      // ... configuration-dependent fields
      $bFormUsername = false;
      $bFormPasswordReset = false;
      $bFormPasswordNonce = false;
      $bFormPasswordOld = false;
      if($this->amCONFIG['password_nonce']) {
        if($this->amCONFIG['password_reset'])
          $bFormPasswordReset = true;
        else
          $bFormPasswordNonce = true;
      }
      if(in_array($this->amCONFIG['authentication_method'], array('none', 'captcha'))) {
        $bFormUsername = true;
        $bFormPasswordOld = true;
      }
      if($this->amCONFIG['credentials_check_method'] != 'none') {
        $bFormPasswordOld = true;
      }

      // ... HTML
      $sHTML .= '<FORM ID="UPwdChg_form" METHOD="post" ACTION="'.$_SERVER['SCRIPT_NAME'].'?view=password-change">';
      $sHTML .= '<INPUT TYPE="hidden" NAME="do" VALUE="password-change" />';
      $sHTML .= '<INPUT TYPE="password" NAME="autocomplete_off" STYLE="DISPLAY:none;" />';
      if(!$bFormPasswordNonce)
        $sHTML .= '<INPUT TYPE="hidden" NAME="password_nonce" />';
      if(!$bFormPasswordOld)
        $sHTML .= '<INPUT TYPE="hidden" NAME="password_old" />';
      $sHTML .= '<TABLE CELLSPACING="0">';
      $iTabIndex = 1;

      // ... password reset
      if($bFormPasswordReset)
        $sHTML .= '<TR><TD CLASS="link" COLSPAN="2"><A HREF="?view=password-nonce-request">'.htmlentities($this->getText('label:password_reset')).'</A></TD></TR>';

      // ... username
      if($bFormUsername)
        $sHTML .= '<TR><TD CLASS="label">'.htmlentities($this->getText('label:username')).':</TD><TD CLASS="input"><SPAN CLASS="required"><INPUT TYPE="text" NAME="username" TABINDEX="'.$iTabIndex++.'" VALUE="'.htmlentities($this->getFormData('username')).'" /></SPAN></TD></TR>';
      else
        $sHTML .= '<TR><TD CLASS="label">'.htmlentities($this->getText('label:username')).':</TD><TD CLASS="input"><SPAN CLASS="readonly"><INPUT TYPE="text" NAME="username" VALUE="'.htmlentities($this->getFormData('username')).'" READONLY="1" /></SPAN></TD></TR>';

      // Note: we do not enforce password maximum length during input,
      // for it would be confusing given the obfuscated data.

      // ... password (nonce; two-factor password change)
      if($bFormPasswordNonce)
        $sHTML .= '<TR><TD CLASS="label">'.htmlentities($this->getText('label:password_nonce')).':</TD><TD CLASS="input"><SPAN CLASS="required"><INPUT TYPE="password" NAME="password_nonce" TABINDEX="'.$iTabIndex++.'" /></SPAN></TD></TR>';
      // ... password (old)
      if($bFormPasswordOld)
        $sHTML .= '<TR><TD CLASS="label">'.htmlentities($this->getText('label:password_old')).':</TD><TD CLASS="input"><SPAN CLASS="required"><INPUT TYPE="password" NAME="password_old" TABINDEX="'.$iTabIndex++.'" /></SPAN></TD></TR>';
      // ... password (new)
      $sHTML .= '<TR><TD CLASS="label">'.htmlentities($this->getText('label:password_new')).':</TD><TD CLASS="input"><SPAN CLASS="required"><INPUT TYPE="password" NAME="password_new" TABINDEX="'.$iTabIndex++.'" /></SPAN></TD></TR>';
      // ... password (confirm)
      $sHTML .= '<TR><TD CLASS="label">'.htmlentities($this->getText('label:password_confirm')).':</TD><TD CLASS="input"><SPAN CLASS="required"><INPUT TYPE="password" NAME="password_confirm" TABINDEX="'.$iTabIndex++.'" /></SPAN></TD></TR>';
      // ... password (policy)
      $sHTML .= '<TR><TD CLASS="label">&nbsp;</TD><TD CLASS="link"><A HREF="?view=password-policy&back=password-change">'.htmlentities($this->getText('label:password_policy')).'</A></TD></TR>';

      // ... submit
      $sHTML .= '<TR><TD CLASS="button" COLSPAN="2"><BUTTON TYPE="submit" TABINDEX="'.$iTabIndex.'">'.htmlentities($this->getText('label:submit')).'</BUTTON></TD></TR>';
      $sHTML .= '</TABLE>';
      $sHTML .= '</FORM>';
      break;

    case 'password-reset':
      if(!$this->amCONFIG['password_nonce'] or !$this->amCONFIG['password_reset']) {
        trigger_error('['.__METHOD__.'] Invalid view request (password-reset); IP='.$this->sRemoteIP, E_USER_WARNING);
        throw new Exception($this->getText('error:internal_error'));
      }

      // ... HTML
      $sHTML .= '<FORM ID="UPwdChg_form" METHOD="post" ACTION="'.$_SERVER['SCRIPT_NAME'].'?view=password-reset">';
      $sHTML .= '<INPUT TYPE="hidden" NAME="do" VALUE="password-reset" />';
      $sHTML .= '<INPUT TYPE="password" NAME="autocomplete_off" STYLE="DISPLAY:none;" />';
      $sHTML .= '<TABLE CELLSPACING="0">';
      $iTabIndex = 1;

      // ... username
      $sHTML .= '<TR><TD CLASS="label">'.htmlentities($this->getText('label:username')).':</TD><TD CLASS="input"><SPAN CLASS="required"><INPUT TYPE="text" NAME="username" TABINDEX="'.$iTabIndex++.'" VALUE="'.htmlentities($this->getFormData('username')).'" /></SPAN></TD></TR>';

      // ... password (nonce)
      $sHTML .= '<TR><TD CLASS="label">'.htmlentities($this->getText('label:password_nonce')).':</TD><TD CLASS="input"><SPAN CLASS="required"><INPUT TYPE="password" NAME="password_nonce" TABINDEX="'.$iTabIndex++.'" /></SPAN></TD></TR>';

      // Note: we do not enforce password maximum length during input,
      // for it would be confusing given the obfuscated data.

      // ... password (new)
      $sHTML .= '<TR><TD CLASS="label">'.htmlentities($this->getText('label:password_new')).':</TD><TD CLASS="input"><SPAN CLASS="required"><INPUT TYPE="password" NAME="password_new" TABINDEX="'.$iTabIndex++.'" /></SPAN></TD></TR>';
      // ... password (confirm)
      $sHTML .= '<TR><TD CLASS="label">'.htmlentities($this->getText('label:password_confirm')).':</TD><TD CLASS="input"><SPAN CLASS="required"><INPUT TYPE="password" NAME="password_confirm" TABINDEX="'.$iTabIndex++.'" /></SPAN></TD></TR>';
      // ... password (policy)
      $sHTML .= '<TR><TD CLASS="label">&nbsp;</TD><TD CLASS="link"><A HREF="?view=password-policy&back=password-reset">'.htmlentities($this->getText('label:password_policy')).'</A></TD></TR>';

      // ... submit
      $sHTML .= '<TR><TD CLASS="button" COLSPAN="2"><BUTTON TYPE="submit" TABINDEX="'.$iTabIndex.'">'.htmlentities($this->getText('label:submit')).'</BUTTON></TD></TR>';
      $sHTML .= '</TABLE>';
      $sHTML .= '</FORM>';
      break;

    }

    // Done
    return $sHTML;
  }


  /*
   * METHODS: Captcha
   ********************************************************************************/

  /** Generate a random color code (in <SAMP>#FFFFFF</SAMP> format)
   *
   * @return string Random HTML code
   */
  private static function getCaptchaColor() {
    $sOutput='#';
    for($i=1; $i<=6; $i++) $sOutput .= dechex(rand(0, 15));
    return $sOutput;
  }

  /** Generate and display a Captcha image
   *
   * <P><B>SYNOPSIS:</B> This function generates a Captcha image, in PNG format
   * and sends its raw content as output (cf. <SAMP>readfile</SAMP>).
   */
  public function outputCaptcha() {
    // Load PEAR::Text_CAPTCHA extension
    require_once 'PEAR.php';
    require_once 'Text/CAPTCHA.php';

    try {
      // Create CAPTCHA
      // ... create Captcha object
      $oCaptcha = Text_CAPTCHA::factory('Image');
      $sFontFile = $this->getResourcesDirectory().'/captcha.ttf';
      $oReturn = $oCaptcha->init(
        array(
          'width' => $this->amCONFIG['captcha_width'],
          'height' => $this->amCONFIG['captcha_height'],
          'output' => 'png',
          'imageOptions' => array(
            'font_size' => $this->amCONFIG['captcha_fontsize'],
            'font_path' => dirname( $sFontFile ),
            'font_file' => basename( $sFontFile ),
            'text_color' => self::getCaptchaColor(),
            'lines_color' => self::getCaptchaColor(),
            'background_color' => self::getCaptchaColor()
          )
        )
      );
      if(PEAR::isError($oReturn)) {
        trigger_error('['.__METHOD__.'] Failed to instantiate captcha object; '.$oReturn->getMessage(), E_USER_WARNING);
        throw new Exception($this->getText('error:internal_error'));
      }
      // ... save the Captcha secret phrase
      $_SESSION['UPwdChg_Captcha_Challenge'] = $oCaptcha->getPhrase();

      // Send Captcha image (as PNG)
      // ... create image object
      $binImage = $oCaptcha->getCAPTCHA();
      if(PEAR::isError($binImage)) {
        trigger_error('['.__METHOD__.'] Failed to generate captcha image; '.$binImage->getMessage(), E_USER_WARNING);
        throw new Exception($this->getText('error:internal_error'));
      }
      // ... save image to (temporary) file (Note: only way to send the image in a binary-safe way)
      $sImagePath = tempnam(sys_get_temp_dir(), 'UPwdChg_Captcha.');
      file_put_contents($sImagePath, $binImage);
      // ... send HTTP headers and content
      header( 'Content-Type: image/png' );
      header( 'Content-Length: '.filesize($sImagePath));
      header( 'Expires: 0' );
      header( 'Cache-Control: must-revalidate, post-check=0, pre-check=0' );
      header( 'Pragma: public' );
      readfile($sImagePath);
      // ... delete the image file
      unlink($sImagePath);
    }
    catch( Exception $e ) {
      echo $e->getMessage();
    }
  }

}
