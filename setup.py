#!/usr/bin/env python
# -*- mode:python; tab-width:4; c-basic-offset:4; intent-tabs-mode:nil; -*-
# ex: filetype=python tabstop=4 softtabstop=4 shiftwidth=4 expandtab autoindent smartindent

# Modules
from distutils.core import setup
import os

# Helpers
def filesInDir( sDirectory ):
    __lsfilesInDir = list()
    for __sFile in os.listdir( sDirectory ):
        __sFile = sDirectory.rstrip( os.sep )+os.sep+__sFile
        if os.path.isfile( __sFile ):
            __lsfilesInDir.append( __sFile )
    return __lsfilesInDir

# Setup
setup(
    name = 'upwdpkg',
    description = 'Universal Password Changer (UPwdChg)',
    long_description = \
        """
        The Universal Password Changer (UPwdChg) allows one to synchronize passwords
        between multiple and different user directory systems - LDAP, MIT Kerberos,
        Microsoft Active Directory, etc. - with an emphasis on flexibility, customiz-
        ability and untrusted frontends security.

        The Universal Password Changer (UPwdChg) is split in two parts:
         - a frontend, running on any user-accessible (untrusted) host, which allows
           users to request password changes
         - a backend, running on a (trusted) management host, where password change
           requests are processed

        In order to deal with the lower security of the frontend host, public key
        cryptography is used:
         - on the frontend, password change requests are encrypted as password
           change tokens, using the RSA public key of the processing backend
         - password change tokens are saved in a storage location shared between
           the frontend and the backend (e.g. NFS, CIFS, SSHFS, rsync, etc.)
         - on the backend, password change tokens are decrypted using the backend
           RSA private key, and processed through customizable plugins

        Password change tokens are actually made of:
         - the password change data - request timestamp, username, old and new
           passwords - along corresponding SHA-256 digest, encrypted using
           AES-256-CBC symetric cipher and base64 encoded
         - the symetric cipher key and initialization vector (IV), encrypted with
           the supplied RSA public key and base64-encoded

        Once decrypted, password change tokens/requests are processed through various
        user-customizable plugins:
         - validation plugins, checking credentials validity, password policies
           compliance, etc.
         - actual password change plugins, performing the requested password change
               on multiple and different backends, such as LDAP, MIT Kerberos, Microsoft
               Active Directory, etc.
             - any other tasks that may be required as part of a password change operation
        """,
    version = os.environ.get('VERSION'),
    author = 'Cedric Dufour',
    author_email = 'http://cedric.dufour.name',
    license = 'GPL-3',
    url = 'http://cedric.dufour.name/software/upwdchg',
    download_url = 'https://github.com/cedric-dufour/upwdchg',
    packages = [ 'UPwdChg', 'UPwdChg.Util' ],
    package_dir = { '': 'backend' },
    requires = [ 'M2Crypto', 'argparse', 'configobj', 'daemon', 'ldap' ],
    scripts = [ 'backend/upwdchg-token', 'backend/upwdchg-process', 'backend/upwdchg-daemon' ],
    data_files = [
        ( 'share/upwdchg/backend/plugins', filesInDir( 'backend/plugins' ) ),
        ( 'share/upwdchg/backend', [ 'backend/upwdchg.conf.spec', 'backend/upwdchg.conf.sample' ] ),
        ],
    )
