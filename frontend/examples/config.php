<?php
/** Universal Password Changer (UPwdChg)
 *
 * @package    UPwdChg
 * @subpackage Examples
 */

################################################################################
# GENERAL SETTINGS
################################################################################

# Comman-separated list of supported locales, the first being the default.
#$_CONFIG['locales'] = 'en,fr'; // string

# Enforce encrypted channel (SSL) usage
#$_CONFIG['force_ssl'] = 1; // integer

# Enforce session statefulness throughout the entire password change/reset operation
#$_CONFIG['strict_session'] = 1; // integer

# Resources (localized HTML snippets, e-mail templates, text lables/messages;
# fonts) directory.
# ATTENTION: This directory MUST be readable (but NOT writable) by PHP!
#$_CONFIG['resources_directory'] = dirname(__FILE__).'/data/UPwdChg/resources'; // is_readable(path)

# Tokens directory (private)
# ATTENTION: This directory MUST be writable by PHP!
# CRITICAL: THIS DIRECTORY MUST NOT BE ACCESSIBLE FROM THE WEB!!!
#$_CONFIG['tokens_directory_private'] = '/var/lib/upwdchg/tokens/private.d'; // is_writable(path)

# Tokens directory (public)
# ATTENTION: This directory MUST be readable by PHP!
# CRITICAL: THIS DIRECTORY MUST NOT BE ACCESSIBLE FROM THE WEB!!!
#$_CONFIG['tokens_directory_public'] = '/var/lib/upwdchg/tokens/public.d'; // is_readable(path)

# RSA public key file (PEM formatted).
#$_CONFIG['public_key_file'] = '/etc/upwdchg/public.pem'; // is_readable(path)

# PHP-MCrypt random source (used to generate encryption data key/IV)
#$_CONFIG['random_source'] = MCRYPT_DEV_URANDOM; // integer

# Authentication method. Available methods are:
#  'http': authentication is handled by the web server [recommended]
#  'ldap': authenticate via configured LDAP server (see below)
#  'captcha': "authenticate" via configured CAPTCHA (see below)
#  'none': no authentication [not recommended]
#$_CONFIG['authentication_method'] = 'http'; // string

# Authentication exempted actions/views. Examples:
#  array(): no exemption [recommended]
#  array('password-change'): make sure to use $_CONFIG['credentials_check_method'] != 'none' (see below)
#  array('password-nonce-request'): VERY BAD IDEA! (exposes your backend to nonce abuse/DoS)
#$_CONFIG['authentication_exempt'] = array(); // array(string)


################################################################################
# PASSWORD (POLICY) SETTINGS
################################################################################

# Credentials check method. Available methods are:
#  'ldap': check credentials via configured LDAP server (see below)
#  'none': no credentials check [not recommended]
#$_CONFIG['credentials_check_method'] = 'ldap'; // string

# Enable password nonce (PIN code) feature
# NOTE: This enables two-factor password change or password reset (see below)
#$_CONFIG['password_nonce'] = 0; // integer

# Enable password reset (forgotten password) feature
# ATTENTION: This also REQUIRES:
#   $_CONFIG['authentication_method']' = 'captcha';  # or 'none'
#   $_CONFIG['password_nonce']' = 1;
#$_CONFIG['password_reset'] = 0; // integer

# Minimum password length.
#$_CONFIG['password_length_minimum'] = 8; // integer

# Maximum password length.
#$_CONFIG['password_length_maximum'] = 64; // integer

# Non-ASCII character requirement.
# -1 = forbid; 1 = require; 0 = ignore
#$_CONFIG['password_charset_notascii'] = -1; // integer

# Lowercase character requirement.
# -1 = forbid; 1 = require; 0 = ignore
#$_CONFIG['password_type_lower'] = 0; // integer

# Uppercase character requirement.
# -1 = forbid; 1 = require; 0 = ignore
#$_CONFIG['password_type_upper'] = 0; // integer

# Digit character requirement.
# -1 = forbid; 1 = require; 0 = ignore
#$_CONFIG['password_type_digit'] = 0; // integer

# Punctuation character requirement.
# -1 = forbid; 1 = require; 0 = ignore
#$_CONFIG['password_type_punct'] = 0; // integer

# Special character requirement.
# -1 = forbid; 1 = require; 0 = ignore
#$_CONFIG['password_type_other'] = 0; // integer

# Minimum different character type (complexity) requirement.
# -1 = forbid; 1 = require; 0 = ignore
#$_CONFIG['password_type_minimum'] = 0; // integer


################################################################################
# LDAP SETTINGS
################################################################################

# LDAP server host URI
#$_CONFIG['ldap_host'] = 'ldap://ldap.example.org'; // string

# LDAP server port
#$_CONFIG['ldap_port'] = 389; // integer

# User DN; '%{USERNAME}' shall be replaced by actual username
# NOTE: If empty, user DN shall be searched for (see below)
#$_CONFIG['ldap_user_dn'] = 'uid=%{USERNAME},ou=users,dc=example,dc=org'; // string

# User base (search) DN
#$_CONFIG['ldap_user_base_dn'] = 'ou=users,dc=example,dc=org'; // string

# User search scope ('base', 'one' or 'subtree').
#$_CONFIG['ldap_user_search_scope'] = 'one'; // string

# User search filter; '%{USERNAME}' shall be replaced by actual username
#$_CONFIG['ldap_user_filter'] = '(&(objectClass=*)(uid=%{USERNAME}))'; // string

# Bind DN (allowing user base DN search)
#$_CONFIG['ldap_bind_dn'] = ''; // string

# Bind password
#$_CONFIG['ldap_bind_password'] = ''; // string

# LDAP protocol version (ignored if <= 0)
#$_CONFIG['ldap_protocol_version'] = 0; // integer


################################################################################
# CAPTCHA SETTINGS
################################################################################

# Captcha image's width, height and font size.
#$_CONFIG['captcha_width'] = 240; // integer
#$_CONFIG['captcha_height'] = 120; // integer
#$_CONFIG['captcha_fontsize'] = 32; // integer

# Captcha Time-to-Live, in number of times it is checked (pages loaded)
#$_CONFIG['captcha_ttl'] = 10; // integer
