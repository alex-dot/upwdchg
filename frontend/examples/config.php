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

# Resources (localized HTML snippets, e-mail templates, text lables/messages;
# fonts) directory.
# ATTENTION: This directory MUST be readable (but NOT writable) by PHP!
#$_CONFIG['resources_directory'] = dirname( __FILE__ ).'/data/UPwdChg/resources'; // is_readable( path )

# Tokens directory.
# ATTENTION: This directory MUST be writable (and readable) by PHP!
# CRITICAL: THIS DIRECTORY MUST NOT BE ACCESSIBLE FROM THE WEB!!!
#$_CONFIG['tokens_directory'] = dirname( __FILE__ ).'/data/UPwdChg/tokens'; // is_writable( path )
$_CONFIG['tokens_directory'] = '/var/lib/upwdchg/tokens.d';

# RSA public key file (PEM formatted).
#$_CONFIG['public_key_file'] = '/etc/upwdchg/public.pem'; // is_readable( path )

# PHP-MCrypt random source (used to generate encryption data key/IV)
#$_CONFIG['random_source'] = MCRYPT_DEV_URANDOM; // integer

# Authentication method. Available methods are:
#  'http': authentication is handled by the web server [recommended]
#  'ldap': authenticate via configured LDAP server (see below)
#  'none': no authentication [not recommended]
#$_CONFIG['authentication_method'] = 'http'; // string


################################################################################
# PASSWORD (POLICY) SETTINGS
################################################################################

# Credentials check method. Available methods are:
#  'ldap': check credentials via configured LDAP server (see below)
#  'none': no credentials check [not recommended]
#$_CONFIG['credentials_check_method'] = 'ldap'; // string

# Minimum password length.
#$_CONFIG['password_length_minimum'] = 8; // integer

# Maximum password length.
#$_CONFIG['password_length_maximum'] = 64; // integer

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
#$_CONFIG['ldap_user_dn'] = 'uid=%{USERNAME},ou=users,dc=example,dc=org'; // string

# User base DN; if set, it shall be searched for a valid user DN (and 'ldap_user_dn' ignored)
#$_CONFIG['ldap_user_base_dn'] = ''; // string

# User search scope ('base', 'one' or 'subtree').
#$_CONFIG['ldap_user_search_scope'] = 'one'; // string

# User search filter; '%{USERNAME}' shall be replaced by actual username
#$_CONFIG['ldap_user_filter'] = ''; // string

# Bind DN (allowing user base DN search)
#$_CONFIG['ldap_bind_dn'] = ''; // string

# Bind password
#$_CONFIG['ldap_bind_password'] = ''; // string

