[token]
pending_directory = string( min=1, max=256, default='/var/lib/upwdchg/tokens.d' )
private_key_file = string( min=1, max=256, default='/etc/upwdchg/private.pem' )
plugins_directory = string( min=1, max=256, default='/etc/upwdchg/daemon/plugins.d' )
archive_directory = string( min=0, max=256, default=None )

[process]
interval = integer( min=1, default=60 )
max_errors = integer( min=0, default=1 )

[email]
admin_address = string( min=0, max=256, default='root@localhost.localdomain' )
user_send = boolean( default=False )
user_domain = string( min=1, max=256, default=None )
sender_address = string( min=1, max=256, default='upwdchg@localhost.localdomain' )
subject_prefix = string( min=0, max=256, default='[UPWDCHG] ' )
body_template_file = string( min=0, max=256, default='/etc/upwdchg/daemon/upwdchg-daemon.email.template' )
sendmail_binary = string( min=1, max=256, default='/usr/sbin/sendmail' )

