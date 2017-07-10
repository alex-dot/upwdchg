[token]
private_directory = string( min=1, max=256, default='/var/lib/upwdchg/tokens/private.d' )
private_key_file = string( min=1, max=256, default='/etc/upwdchg/private.pem' )
public_directory = string( min=1, max=256, default='/var/lib/upwdchg/tokens/public.d' )
public_key_file = string( min=1, max=256, default='/etc/upwdchg/public.pem' )
plugins_directory = string( min=1, max=256, default='/etc/upwdchg/daemon/plugins/%{type}.d' )
random_file = string( min=1, max=256, default='/dev/urandom' )
allowed_types = string( min=1, max=256, default='password-change' )
archive_directory = string( min=0, max=256, default=None )

[process]
interval = float( min=1.0, default=60.0 )
max_tokens = integer( min=0, default=100 )
max_errors = integer( min=0, default=1 )

[email]
admin_address = string( min=0, max=256, default='Administrator <root@localhost.localdomain>' )
user_send = boolean( default=False )
user_domain = string( min=1, max=256, default=None )
user_address_from_ldap = boolean( default=False )
sender_address = string( min=1, max=256, default='UPwdChg <upwdchg@localhost.localdomain>' )
subject_prefix = string( min=0, max=256, default='[UPWDCHG] ' )
body_template_file = string( min=0, max=256, default='/etc/upwdchg/daemon/upwdchg-daemon.email.template' )
sendmail_binary = string( min=1, max=256, default='/usr/sbin/sendmail' )
encoding = string( min=1, max=256, default='utf-8' )

[ldap]
uri = string( min=0, max=256, default='ldap://ldap.example.org:389' )
bind_dn = string( min=0, max=256, default='cn=admin,dc=example,dc=org'  )
bind_pwd = string( min=0, max=256, default='' )
user_dn = string( min=0, max=256, default='uid=%{USERNAME},ou=users,dc=example,dc=org' )
search_dn = string( min=0, max=256, default='ou=users,dc=example,dc=org' )
search_scope = option( ldap.SCOPE_BASELEVEL, ldap.SCOPE_ONELEVEL, ldap.SCOPE_SUBTREE, default=ldap.SCOPE_ONELEVEL )
search_filter = string( min=0, max=256, default='(&(objectClass=inetOrgPerson)(uid=%{USERNAME}))' )
email_attribute = string( min=0, max=256, default='mail' )
encoding = string( min=1, max=256, default='utf-8' )
