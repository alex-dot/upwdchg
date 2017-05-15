<?php // INDENTING (emacs/vi): -*- mode:php; tab-width:2; c-basic-offset:2; intent-tabs-mode:nil; -*- ex: set tabstop=2 expandtab:
/** Universal Password Changer (UPwdChg)
 *
 * <P><B>COPYRIGHT:</B></P>
 * <PRE>
 * Universal Password Changer (UPwdChg)
 * Copyright (C) 2014 Cedric Dufour <http://cedric.dufour.name>
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

  /** Symetric cipher algorithm
   * @var string */
  const CIPHER_ALGO = 'aes-256-cbc';

  /** Symetric cipher key length
   * @var int */
  const CIPHER_KEY_LENGTH = 32;

  /** Symetric cipher IV length
   * @var int */
  const CIPHER_IV_LENGTH = 16;

  /** Digest algorithm
   * @var string */
  const DIGEST_ALGO = 'sha256';


  /*
   * FIELDS
   ********************************************************************************/

  /** Configuration parameters
   * @var array|mixed */
  private $amCONFIG;

  /** Form data
   * @var array|mixed */
  private $amFORMDATA;


  /*
   * CONSTRUCTORS
   ********************************************************************************/

  /** Construct and inititalize a new UPwdChg object
   *
   * @param string $sConfigurationPath Configuration file path
   */
  public function __construct($sConfigurationPath) {
    // Fields
    $this->initConfig($sConfigurationPath);
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
    $_CONFIG['resources_directory'] = dirname(__FILE__).'/data/UPwdChg/resources';
    $_CONFIG['tokens_directory'] = dirname(__FILE__).'/data/UPwdChg/tokens';
    $_CONFIG['public_key_file'] = '/etc/upwdchg/public.pem';
    $_CONFIG['random_source'] = MCRYPT_DEV_URANDOM;
    $_CONFIG['authentication_method'] = 'http';
    $_CONFIG['credentials_check_method'] = 'ldap';
    $_CONFIG['password_length_minimum'] = 8;
    $_CONFIG['password_length_maximum'] = 64;
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
    $_CONFIG['ldap_user_base_dn'] = '';
    $_CONFIG['ldap_user_search_scope'] = 'one';
    $_CONFIG['ldap_user_filter'] = '';
    $_CONFIG['ldap_bind_dn'] = '';
    $_CONFIG['ldap_bind_password'] = '';
    $_CONFIG['ldap_protocol_version'] = 0;

    // Load user configuration
    if((include $sConfigurationPath) === false) {
      trigger_error('['.__METHOD__.'] Failed to load configuration', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }

    // Validation
    //echo nl2br(var_export($_CONFIG, true)); // DEBUG
    // ... is integer
    foreach(array('force_ssl', 'random_source',
                  'password_length_minimum', 'password_length_maximum', 'password_charset_notascii',
                  'password_type_lower', 'password_type_upper', 'password_type_digit',
                  'password_type_punct', 'password_type_other', 'password_type_minimum',
                  'ldap_port', 'ldap_protocol_version',
    ) as $p)
      if(!is_int($_CONFIG[$p]))
        trigger_error('['.__METHOD__.'] Parameter must be an integer ('.$p.')', E_USER_ERROR);
    // ... is string
    foreach(array('locales', 'authentication_method', 'credentials_check_method',
                  'ldap_host', 'ldap_user_dn', 'ldap_user_base_dn', 'ldap_user_search_scope',
                  'ldap_user_filter', 'ldap_bind_dn', 'ldap_bind_password',
    ) as $p)
      if(!is_string($_CONFIG[$p]))
        trigger_error('['.__METHOD__.'] Parameter must be a string ('.$p.')', E_USER_ERROR);
    // ... is readable
    foreach(array('resources_directory', 'public_key_file') as $p)
      if(!is_readable($_CONFIG[$p]))
        trigger_error('['.__METHOD__.'] Parameter must be a readable path ('.$p.')', E_USER_ERROR);
    // ... is writeable
    foreach(array('tokens_directory') as $p)
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
      $_TEXT['label:username'] = 'Username';
      $_TEXT['label:password_old'] = 'Old Password';
      $_TEXT['label:password_new'] = 'New Password';
      $_TEXT['label:password_confirm'] = '(confirm)';
      $_TEXT['label:password_policy'] = '(password policy)';
      $_TEXT['label:password_policy_back'] = '(back)';
      $_TEXT['label:submit'] = 'Submit';
      $_TEXT['error:internal_error'] = 'Internal error. Please contact the system administrator.';
      $_TEXT['error:unsecure_channel'] = 'Unsecure channel. Please use an encrypted channel (SSL).';
      $_TEXT['error:invalid_form_data'] = 'Invalid form data. Please contact the system administrator.';
      $_TEXT['error:invalid_credentials'] = 'Invalid credentials (incorrect username or old password).';
      $_TEXT['error:password_mismatch'] = 'Password confirmation mismatch.';
      $_TEXT['error:password_identical'] = 'Old and new passwords are identical.';
      $_TEXT['error:password_length_minimum'] = 'Password MUST contain at least '.$this->amCONFIG['password_length_minimum'].' characters.';
      $_TEXT['error:password_length_maximum'] = 'Password may NOT contain more than '.$this->amCONFIG['password_length_maximum'].' characters.';
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


  /*
   * METHODS: Authentication
   ********************************************************************************/

  /** Authenticate via user-configured authentication backend
   *
   * @return array|string User credentials (username, password), Null if no authentication is configured
   */
  private function authenticate() {
    switch($this->amCONFIG['authentication_method']) {
    case 'http':
      return $this->authenticateHttp();
    case 'ldap':
      return $this->authenticateLdap();
    case 'none':
      return null;
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
    if(!isset($_SERVER['PHP_AUTH_USER'])) {
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
    if(!isset($_SERVER['PHP_AUTH_USER'])) {
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

  /** Check credentials via user-configured authentication backend
   *
   * @param string $sUsername Username
   * @param string $sPassword Password
   * @return boolean True for valid credentials, False otherwise
   */
  private function checkCredentials($sUsername, $sPassword) {
    switch($this->amCONFIG['credentials_check_method']) {
    case 'ldap':
      return $this->checkCredentialsLdap($sUsername, $sPassword);
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
   * @return boolean True for valid credentials, False otherwise
   */
  private function checkCredentialsLdap($sUsername, $sPassword) {
    // Check crendentials
    $hLdap = null;
    try
    {

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
      if(!empty($this->amCONFIG['ldap_user_base_dn'])
         and !empty($this->amCONFIG['ldap_user_filter'])) {
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
                                    array(), 0, 2);
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
      }

      // ... bind as user
      if(!@ldap_bind($hLdap, $sBindDn, $sBindPassword))
        throw new Exception('Failed to bind to LDAP server; user='.$sUsername);

      // ... unbind
      @ldap_unbind($hLdap);

    }
    catch(Exception $e) {
      @ldap_unbind($hLdap);
      trigger_error('['.__METHOD__.'] '.$e->getMessage(), E_USER_WARNING);
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
   * @return array|int Types array (lower, upper, digit, punct, other, count)
   */
  private static function getPasswordTypes($sPassword) {
    $bNotAscii = false;
    $bLower = false;
    $bUpper = false;
    $bDigit = false;
    $bPunct = false;
    $bOther = false;
    $iType = 0;
    foreach(str_split($sPassword) as $sCharacter) {
      if(ord($sCharacter) > 127)
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
    return array('notascii' => $bNotAscii,
                 'lower' => $bLower,
                 'upper' => $bUpper,
                 'digit' => $bDigit,
                 'punct' => $bPunct,
                 'other' => $bOther,
                 'count' => $iType);
  }

  /** Check password policy
   *
   * @param string $sPassword_new New password
   * @param string $sPassword_confirm New password confirmation
   * @param string $sPassword_old Old password
   */
  private function checkPasswordPolicy($sPassword_new, $sPassword_confirm, $sPassword_old=null) {
    $asPasswordErrors = array();

    // Check password confirmation
    if($sPassword_new != $sPassword_confirm)
      throw new Exception($this->getText('error:password_mismatch'));

    // Check no-change password
    if(isset($sPassword_old) and $sPassword_new == $sPassword_old)
      throw new Exception($this->getText('error:password_identical'));

    // Check minimum length
    if($this->amCONFIG['password_length_minimum']) {
      if(mb_strlen($sPassword_new) < $this->amCONFIG['password_length_minimum'])
        array_push($asPasswordErrors, $this->getText('error:password_length_minimum'));
    }

    // Check maximum length
    if($this->amCONFIG['password_length_maximum']) {
      if(mb_strlen($sPassword_new) > $this->amCONFIG['password_length_maximum'])
        array_push($asPasswordErrors, $this->getText('error:password_length_maximum'));
    }

    // Check password characters type
    $aiPasswordTypes = $this->getPasswordTypes($sPassword_new);
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


  /*
   * METHODS: Token
   ********************************************************************************/

  /** Return the "password-change" token data (associative array)
   *
   * @param int $iNow Current time (epoch)
   * @param string $sUsername Username
   * @param string $sPassword_old Old password
   * @param string $sPassword_new New password
   * @return array|string Token data
   */
  private function getTokenData_PasswordChange($iNow, $sUsername, $sPassword_old, $sPassword_new)
  {
    // Associative array
    return array(
      'timestamp' => gmdate('Y-m-d\TH:i:s\Z', $iNow),
      'username' => $sUsername,
      'password-old' => $sPassword_old,
      'password-new' => $sPassword_new,
    );
  }

  /** Return the encrypted token
   *
   * @param array|string $asData Token data
   * @return string Token
   */
  private function encryptToken($asData)
  {
    // Load the RSA public key
    $sPublicKey = file_get_contents($this->amCONFIG['public_key_file']);
    if($sPublicKey === false) {
      trigger_error('['.__METHOD__.'] Failed to load RSA public key', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }
    $mPublicKey = openssl_pkey_get_public($sPublicKey);
    if($mPublicKey === false) {
      trigger_error('['.__METHOD__.'] Invalid RSA public key', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }

    // Random material
    $sCipherKey = mcrypt_create_iv(UPwdChg::CIPHER_KEY_LENGTH, $this->amCONFIG['random_source']);
    $sCipherIv = mcrypt_create_iv(UPwdChg::CIPHER_IV_LENGTH, $this->amCONFIG['random_source']);
    $sCipherKeyIv = $sCipherKey.$sCipherIv;

    // Encrypt the symmetric key and initialization vector (IV)
    if(openssl_public_encrypt($sCipherKeyIv, $sCipherKeyIvEncrypted, $mPublicKey, OPENSSL_PKCS1_OAEP_PADDING) === false) {
      trigger_error('['.__METHOD__.'] Failed to encrypt symmetric key/IV', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }

    // Data
    $sData = implode("\n", $asData);

    // Digest
    $sDataDigest = openssl_digest($sData, UPwdChg::DIGEST_ALGO, true);
    if($sDataDigest === false) {
      trigger_error('['.__METHOD__.'] Failed to compute data digest', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }
    $sData = base64_encode($sDataDigest)."\n".$sData;

    // Encrypt
    $sDataEncrypted = openssl_encrypt($sData, UPwdChg::CIPHER_ALGO, $sCipherKey, true, $sCipherIv);
    if($sDataEncrypted === false) {
      trigger_error('['.__METHOD__.'] Failed to encrypt data', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }

    // Token
    $asToken = array('format' => '# UNIVERSAL PASSWORD CHANGER TOKEN, V1.0',
                     'key' => base64_encode($sCipherKeyIvEncrypted),
                     'data' => base64_encode($sDataEncrypted));
    return implode("\n", $asToken);
  }

  /** Write the given token to file
   *
   * @param int $iNow Current time (epoch)
   * @param string $sToken Token
   */
  private function writeToken($iNow, $sToken)
  {
    // Write the token to storage
    $sFile = $this->amCONFIG['tokens_directory'].DIRECTORY_SEPARATOR.gmdate('Ymd\THis\Z-', $iNow).bin2hex(openssl_random_pseudo_bytes(8)).'.token';
    $iUMask_old = umask();
    umask(0137);
    if(file_put_contents($sFile, $sToken) != strlen($sToken)) {
      umask($iUMask_old);
      trigger_error('['.__METHOD__.'] Failed to write token to file', E_USER_WARNING);
      throw new Exception($this->getText('error:internal_error'));
    }
    umask($iUMask_old);
  }

  /** Write the encrypted "password-change" token to file
   *
   * @param string $sUsername Username
   * @param string $sPassword_old Old password
   * @param string $sPassword_new New password
   */
  private function writeToken_PasswordChange($sUsername, $sPassword_old, $sPassword_new)
  {
    $iNow = time();
    $asData = $this->getTokenData_PasswordChange($iNow, $sUsername, $sPassword_old, $sPassword_new);
    $sToken = $this->encryptToken($asData);
    $this->writeToken($iNow, $sToken);
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
    $sError = null;
    $sView = 'default';
    $amFormData = array();
    $sDo = isset($_POST['do']) ? $_POST['do'] : (isset($_GET['view']) ? $_GET['view'] : null);
    try
    {
      // Check encryption
      if($this->amCONFIG['force_ssl'] and !isset($_SERVER['HTTPS'])) {
        throw new Exception($this->getText('error:unsecure_channel'));
      }

      // Credentials
      $sUsername = '';
      $sPassword_old = '';
      $sPassword_new = '';

      // Check authentication
      if($this->amCONFIG['authentication_method'] != 'none') {
        $asCredentials = $this->authenticate();
        $sUsername = $amFormData['username'] = $asCredentials['username'];
        $sPassword_old = $asCredentials['password'];
      }

      // Form submission handling
      switch($sDo) {

      case 'locale':
        // Retrieve form variables
        if(!isset($_POST['locale']) or !is_scalar($_POST['locale'])) {
          trigger_error('['.__METHOD__.'] Invalid form data (locale); IP='.(isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown'), E_USER_WARNING);
          throw new Exception($this->getText('error:invalid_form_data'));
        }
        $sLocale = trim($_POST['locale']);

        // Check and set locale
        if(!in_array($sLocale, $this->getSupportedLocales())) {
          trigger_error('['.__METHOD__.'] Invalid locale; IP='.(isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown'), E_USER_WARNING);
          throw new Exception($this->getText('error:invalid_form_data'));
        }
        $_SESSION['UPwdChg_Locale'] = $sLocale;

        // View
        if(isset($_GET['view']))
          $sView = $_GET['view'];
        break;

      case 'password-change':
        // Retrieve arguments
        if(!isset($_POST['username'], $_POST['password_old'], $_POST['password_new'], $_POST['password_confirm'])
           or !is_scalar($_POST['username']) or strlen($_POST['username']) > 1000
           or !is_scalar($_POST['password_old']) or strlen($_POST['password_old']) > 1000
           or !is_scalar($_POST['password_new']) or strlen($_POST['password_new']) > 1000
           or !is_scalar($_POST['password_confirm']) or strlen($_POST['password_confirm']) > 1000) {
          trigger_error('['.__METHOD__.'] Invalid form data (request:arguments); IP='.(isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown'), E_USER_WARNING);
          throw new Exception($this->getText('error:invalid_form_data'));
        }
        if($this->amCONFIG['authentication_method'] == 'none')
          $sUsername = $amFormData['username'] = $_POST['username'];
        if($this->amCONFIG['authentication_method'] == 'none'
           or $this->amCONFIG['credentials_check_method'] != 'none')
          $sPassword_old = $_POST['password_old'];
        $sPassword_new = $_POST['password_new'];
        $sPassword_confirm = $_POST['password_confirm'];

        // Check credentials
        if($this->amCONFIG['credentials_check_method'] != 'none') {
          if(!$this->checkCredentials($sUsername, $sPassword_old))
            throw new Exception($this->getText('error:invalid_credentials'));
        }

        // Check password policy
        $this->checkPasswordPolicy($sPassword_new, $sPassword_confirm, $sPassword_old);

        // Write token
        $this->writeToken_PasswordChange($sUsername, $sPassword_old, $sPassword_new);

        // Clear session (prevent replay of current session)
        session_regenerate_id(true);

        // Redirect (prevent form resubmission)
        echo '<SCRIPT TYPE="text/javascript">document.location.replace(\'?view=password-change-confirm\')</SCRIPT>';
        echo '<META HTTP-EQUIV="refresh" CONTENT="1;URL=?view=password-change-confirm" />';
        exit;

      case 'password-change-confirm':
        // View
        $sView = 'password-change-confirm';
        break;

      case 'password-policy':
        // View
        $sView = 'password-policy';
        break;

      default:
        // Nothing to do here
        break;

      }

    }
    catch(Exception $e) {
      // Save the error message
      $sError = $e->getMessage();
    }

    // Save form data
    $this->amFORMDATA = array_merge(array('VIEW' => $sView, 'ERROR' => $sError), $amFormData);

    // Done
    return $this->amFORMDATA['VIEW'];
  }

  /** Retrieve data (variable value) from the controller
   *
   * @param string $sID Data (variable) ID
   * @return mixed Data (variable) value
   */
  public function getFormData($sID) {
    return $this->amFORMDATA[ $sID ];
  }

  /** Retrieve the form's HTML code from the controller (for the given view)
   *
   * @param string $sID Form ID
   * @return string Form's HTML code
   */
  public function getFormHtml($sID) {
    // Build form
    $sHTML = '';
    switch($sID) {

    case 'locale':
      $sView = isset($_GET['view']) ? $_GET['view'] : null;
      $sCurrentLocale = $this->getCurrentLocale();
      $sHTML .= '<FORM METHOD="post" ACTION="'.$_SERVER['SCRIPT_NAME'].($sView ? '?view='.$sView : null).'">';
      $sHTML .= '<INPUT TYPE="hidden" NAME="do" VALUE="locale" />';
      $sHTML .= '<TABLE CELLSPACING="0"><TR>';
      $sHTML .= '<TD CLASS="label">'.htmlentities($this->getText('label:language')).':</TD>';
      $sHTML .= '<TD CLASS="input"><SELECT NAME="locale" ONCHANGE="javascript:submit();" STYLE="WIDTH:50px;">';
      foreach($this->getSupportedLocales() as $sLocale) {
        $sHTML .= '<OPTION VALUE="'.$sLocale.'"'.($sLocale == $sCurrentLocale ? ' SELECTED' : null).'>'.$sLocale.'</OPTION>';
      }
      $sHTML .= '</SELECT></TD>';
      $sHTML .= '</TR></TABLE>';
      $sHTML .= '</FORM>';
      break;

    case 'password-policy':
      $sCurrentLocale = $this->getCurrentLocale();
      $sHTML .= '<UL>';
      if($this->amCONFIG['password_length_minimum'])
        $sHTML .= '<LI>'.htmlentities($this->getText('error:password_length_minimum')).'</LI>';
      if($this->amCONFIG['password_length_maximum'])
        $sHTML .= '<LI>'.htmlentities($this->getText('error:password_length_maximum')).'</LI>';
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
      $sHTML .= '<P CLASS="link"><A HREF="?">'.htmlentities($this->getText('label:password_policy_back')).'</A></P>';
      break;

    case 'password-change':
      $bFormUsername = ($this->amCONFIG['authentication_method'] == 'none');
      $bFormPassword_old = ($this->amCONFIG['authentication_method'] == 'none'
                            or $this->amCONFIG['credentials_check_method'] != 'none');
      $sHTML .= '<FORM METHOD="post" ACTION="'.$_SERVER['SCRIPT_NAME'].'">';
      $sHTML .= '<INPUT TYPE="hidden" NAME="do" VALUE="password-change" />';
      $sHTML .= '<INPUT TYPE="password" NAME="autocomplete_off" STYLE="DISPLAY:none;" />';
      if(!$bFormPassword_old)
        $sHTML .= '<INPUT TYPE="hidden" NAME="password_old" />';
      $sHTML .= '<TABLE CELLSPACING="0">';
      $iTabIndex = 1;

      // ... username
      if($bFormUsername)
        $sHTML .= '<TR><TD CLASS="label">'.htmlentities($this->getText('label:username')).':</TD><TD CLASS="input"><SPAN CLASS="required"><INPUT TYPE="text" NAME="username" TABINDEX="'.$iTabIndex++.'" VALUE="'.htmlentities($this->getFormData('username')).'" /></SPAN></TD></TR>';
      else
        $sHTML .= '<TR><TD CLASS="label">'.htmlentities($this->getText('label:username')).':</TD><TD CLASS="input"><SPAN CLASS="readonly"><INPUT TYPE="text" NAME="username" VALUE="'.htmlentities($this->getFormData('username')).'" READONLY="1" /></SPAN></TD></TR>';

      // Note: we do not enforce password maximum length during input,
      // for it would be confusing given the obfuscated data.

      // ... password (old)
      if($bFormPassword_old)
        $sHTML .= '<TR><TD CLASS="label">'.htmlentities($this->getText('label:password_old')).':</TD><TD CLASS="input"><SPAN CLASS="required"><INPUT TYPE="password" NAME="password_old" TABINDEX="'.$iTabIndex++.'" /></SPAN></TD></TR>';
      // ... password (new)
      $sHTML .= '<TR><TD CLASS="label">'.htmlentities($this->getText('label:password_new')).':</TD><TD CLASS="input"><SPAN CLASS="required"><INPUT TYPE="password" NAME="password_new" TABINDEX="'.$iTabIndex++.'" /></SPAN></TD></TR>';
      // ... password (confirm)
      $sHTML .= '<TR><TD CLASS="label">'.htmlentities($this->getText('label:password_confirm')).':</TD><TD CLASS="input"><SPAN CLASS="required"><INPUT TYPE="password" NAME="password_confirm" TABINDEX="'.$iTabIndex++.'" /></SPAN></TD></TR>';
      // ... password (policy)
      $sHTML .= '<TR><TD CLASS="label">&nbsp;</TD><TD CLASS="link"><A HREF="?view=password-policy">'.htmlentities($this->getText('label:password_policy')).'</A></TD></TR>';

      // ... submit
      $sHTML .= '<TR><TD CLASS="button" COLSPAN="2"><BUTTON TYPE="submit" TABINDEX="'.$iTabIndex.'">'.htmlentities($this->getText('label:submit')).'</BUTTON></TD></TR>';
      $sHTML .= '</TABLE>';
      $sHTML .= '</FORM>';
      break;

    }

    // Done
    return $sHTML;
  }

  /** Reset session
   *
   *  Clear the current session and regenerate a new session ID.
   */
  private function resetSession() {
    // Save session locale and login URL
    $sLocale = $this->getCurrentLocale();

    // Clear session and start a new one.
    session_regenerate_id(true);

    // Restore session locale and login URL
    $_SESSION['UPwdChg_Locale'] = $sLocale;
  }

}
