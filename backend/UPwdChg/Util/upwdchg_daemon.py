# -*- mode:python; tab-width:4; c-basic-offset:4; intent-tabs-mode:nil; -*-
# ex: filetype=python tabstop=4 softtabstop=4 shiftwidth=4 expandtab autoindent smartindent

#
# Universal Password Changer (UPwdChg)
# Copyright (C) 2014-2018 Cedric Dufour <http://cedric.dufour.name>
# Author: Cedric Dufour <http://cedric.dufour.name>
#
# The Universal Password Changer (UPwdChg) is free software:
# you can redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, Version 3.
#
# The Universal Password Changer (UPwdChg) is distributed in the hope
# that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# See the GNU General Public License for more details.
#
# SPDX-License-Identifier: GPL-3.0
# License-Filename: LICENSE/GPL-3.0.txt
#

# Modules
# ... deb: python3-configobj, python3-daemon, python3-ldap
from UPwdChg import \
    UPWDCHG_VERSION, \
    UPWDCHG_ENCODING, \
    UPWDCHG_DEFAULT_DIR_PRIVATE, \
    UPWDCHG_DEFAULT_FILE_KEY_PRIVATE, \
    UPWDCHG_DEFAULT_DIR_PUBLIC, \
    UPWDCHG_DEFAULT_FILE_KEY_PUBLIC, \
    UPWDCHG_DEFAULT_DIR_PLUGINS, \
    UPWDCHG_DEFAULT_FILE_RANDOM, \
    UPWDCHG_DEFAULT_ALLOWED_TYPES, \
    TokenReader
from UPwdChg.Util import \
    Process
import argparse as AP
from codecs import \
    open
import configobj as CO
from daemon import \
    DaemonContext
from daemon.runner import \
    emit_message, \
    is_pidfile_stale, \
    make_pidlockfile
from email.mime.text import \
    MIMEText
import os
import signal
from subprocess import \
    Popen, \
    PIPE
import stat
import sys
import syslog
from time import \
    gmtime, \
    sleep, \
    strftime
import validate as VA
try:
    import ldap
    LDAP_AVAILABLE = True
except ImportError:
    LDAP_AVAILABLE = False


#------------------------------------------------------------------------------
# CONSTANTS
#------------------------------------------------------------------------------

UPWDCHG_DAEMON_CONFIGSPEC = 'upwdchg-daemon.conf.spec'


#------------------------------------------------------------------------------
# CLASSES
#------------------------------------------------------------------------------

class Daemon:
    """
    Universal Password Changer Token Processing Daemon
    """

    #------------------------------------------------------------------------------
    # CONSTRUCTORS / DESTRUCTOR
    #------------------------------------------------------------------------------

    def __init__(self):
        # Fields
        self.__bInterrupted = False
        self._bDebug = False
        self._sTokenDirPrivate = UPWDCHG_DEFAULT_DIR_PRIVATE
        self._sTokenFileKeyPrivate = UPWDCHG_DEFAULT_FILE_KEY_PRIVATE
        self._sTokenDirPublic = UPWDCHG_DEFAULT_DIR_PUBLIC
        self._sTokenFileKeyPublic = UPWDCHG_DEFAULT_FILE_KEY_PUBLIC
        self._sTokenDirPlugins = UPWDCHG_DEFAULT_DIR_PLUGINS
        self._sTokenFileRandom = UPWDCHG_DEFAULT_FILE_RANDOM
        self._sTokenAllowedTypes = UPWDCHG_DEFAULT_ALLOWED_TYPES
        self._sTokenDirArchives = None
        self._fProcessInterval = 60.0
        self._iProcessMaxTokens = 100
        self._iProcessMaxErrors = 1
        self._sEmailAdmin = 'Administrator <upwdchg@localhost.localdomain>'
        self._bEmailUser = False
        self._sEmailUserDomain = None
        self._bEmailUserAddressFromLdap = False
        self._sEmailSender = 'UPwdChg <upwdchg@localhost.localdomain>'
        self._sEmailSubjectPrefix = '[UPWDCHG] '
        self._sEmailFileBodyTemplate = '/etc/upwdchg/daemon/upwdchg-daemon.email.template'
        self._sEmailSendmail = '/usr/sbin/sendmail'
        self._sEmailEncoding = UPWDCHG_ENCODING
        self._sLdapUri = 'ldap://ldap.example.org:389'
        self._sLdapBindDN = 'cn=admin,dc=example,dc=org'
        self._sLdapBindPwd = ''
        self._sLdapUserDN = 'uid=%{USERNAME},ou=users,dc=example,dc=org'
        self._sLdapSearchDN = 'ou=users,dc=example,dc=org'
        self._oLdapSearchScope = 'ldap.SCOPE_ONELEVEL'
        self._sLdapSearchFilter = '(&(objectClass=inetOrgPerson)(uid=%{USERNAME}))'
        self._sLdapEmailAttribute = 'mail'
        self._sLdapEncoding = UPWDCHG_ENCODING


    #------------------------------------------------------------------------------
    # METHODS
    #------------------------------------------------------------------------------

    def _signal(self, signal, frame):
        self.__bInterrupted = True


    def _sendmail(self, _sFrom, _sTo, _sSubject, _sBody):
        """
        Send the given e-mail message.
        """

        oMIMEText = MIMEText(_sBody, 'plain')
        oMIMEText['From'] = _sFrom
        oMIMEText['Subject'] = _sSubject
        oMIMEText['To'] = _sTo
        oPopen = Popen([self._sEmailSendmail, '-t'], stdin=PIPE)
        oPopen.communicate(oMIMEText.as_string().encode(sys.stdin.encoding))


    def processTokens(self):
        """
        Watch directory for tokens and process them; returns a non-zero exit code in case of failure.
        """

        # Check tokens directory
        if not os.path.isdir(self._sTokenDirPrivate):
            sys.stderr.write('ERROR[Daemon]: Invalid tokens directory\n')
            return 1
        fDirTokensMTime_1 = 0.0

        # Processing object
        oProcess = Process()
        oProcess.config(
            self._sTokenFileKeyPrivate,
            self._sTokenFileKeyPublic,
            self._sTokenDirPlugins,
            )

        # Loop
        iError = 0
        while True:
            # Check loop conditions
            if self.__bInterrupted:
                break
            if self._iProcessMaxErrors and iError >= self._iProcessMaxErrors:
                sys.stderr.write('CRITICAL[Daemon]: Too-many errors (%d); bailing out\n' % iError)
                if self._sEmailAdmin:
                    try:
                        self._sendmail(self._sEmailSender, self._sEmailAdmin, self._sEmailSubjectPrefix+'Critical Error', 'CRITICAL[Daemon]: Too-many errors (%d); bailing out\n' % iError)
                    except Exception as e:
                        pass
                return 1

            # Check (private/incoming) tokens directory for changes
            try:
                fDirTokensMTime_2 = os.stat(self._sTokenDirPrivate).st_mtime
            except Exception as e:
                iError += 1
                sys.stderr.write('ERROR[Daemon]: Failed to retrieve tokens directory last modification time; %s\n' % str(e))
                fDirTokensMTime_2 = fDirTokensMTime_1
            if (fDirTokensMTime_2 - fDirTokensMTime_1) < 0.1:
                if self._bDebug:
                    sys.stderr.write('DEBUG[Daemon]: Sleeping for %f seconds...\n' % self._fProcessInterval)
                sleep(self._fProcessInterval)
                continue
            if self._bDebug:
                sys.stderr.write('DEBUG[Daemon]: Detected changes in tokens directory\n')

            # List tokens
            lsFilesToken = list()
            try:
                for sFile in os.listdir(self._sTokenDirPrivate):
                    sFile = self._sTokenDirPrivate.rstrip(os.sep)+os.sep+sFile
                    if os.path.isfile(sFile):
                        lsFilesToken.append(sFile)
            except Exception as e:
                iError += 1
                sys.stderr.write('ERROR[Daemon]: Failed to retrieve tokens list; %s\n' % str(e))
                continue
            iFilesToken = len(lsFilesToken)
            if not iFilesToken:
                if fDirTokensMTime_1:
                    sys.stderr.write('WARNING[Daemon]: No password change token found\n')
                fDirTokensMTime_1 = fDirTokensMTime_2
                continue
            if self._iProcessMaxTokens and iFilesToken >= self._iProcessMaxTokens:
                sys.stderr.write('CRITICAL[Daemon]: Too-many tokens (%d); bailing out\n' % iFilesToken)
                if self._sEmailAdmin:
                    try:
                        self._sendmail(self._sEmailSender, self._sEmailAdmin, self._sEmailSubjectPrefix+'Critical Error', 'CRITICAL[Daemon]: Too-many tokens (%d); bailing out\n' % iFilesToken)
                    except Exception as e:
                        pass
                return 1
            lsFilesToken.sort()

            # Update tokens directory last modification time
            fDirTokensMTime_1 = fDirTokensMTime_2

            # Process tokens
            iErrorTokens = 0
            lTokenAllowedTypes = self._sTokenAllowedTypes.replace(' ', '').split(',')
            for sFileToken in lsFilesToken:
                lsOutputs = []
                iErrorToken = 0
                bSkipProcessing = False
                sys.stderr.write('INFO[Daemon]: Processing token; %s\n' % sFileToken)

                # ... token read
                oToken = TokenReader()
                oToken.config(self._sTokenFileKeyPrivate, self._sTokenFileKeyPublic)
                if oToken.readToken(sFileToken):
                    iErrorToken += 1
                    bSkipProcessing = True
                    sys.stderr.write('ERROR[Daemon]: Failed to read token; %s\n' % sFileToken)
                    lsOutputs.append('ERROR[UPwdChg]: Internal error; please contact your system administrator\n')

                # ... token type
                sTokenType = oToken.getType()
                if not sTokenType in lTokenAllowedTypes:
                    iErrorToken += 1
                    bSkipProcessing = True
                    sys.stderr.write('ERROR[Daemon]: Token type not allowed; %s\n' % sTokenType)
                    lsOutputs.append('ERROR[UPwdChg]: Internal error; please contact your system administrator\n')
                if self._bDebug:
                    sys.stderr.write('DEBUG[Daemon]: Allowed token type; %s\n' % sTokenType)

                # ... token processing (plugins)
                if not bSkipProcessing:
                    try:
                        (iReturn, lsOutputs) = oProcess.processToken(sFileToken, _sTokenType=sTokenType)
                        if self._bDebug:
                            sys.stderr.write('DEBUG[Daemon]: Token processing succeeded (exit=%d)\n' % iReturn)
                    except Exception as e:
                        iErrorToken += 1
                        sys.stderr.write('ERROR[Daemon]: Token processing failure\n')
                        lsOutputs = list()

                # ... processing output
                if lsOutputs and (self._sEmailAdmin or self._bEmailUser):
                    sOutput = ''.join(lsOutputs)

                    # ... retrieve token username
                    sUsername = oToken['username']

                    # ... e-mail body template
                    if self._sEmailFileBodyTemplate:
                        try:
                            oFile = open(self._sEmailFileBodyTemplate, 'r', encoding=self._sEmailEncoding)
                            sOutput = (''.join(oFile.readlines())).replace('%{OUTPUT}', sOutput)
                            oFile.close()
                        except Exception as e:
                            iErrorToken += 1
                            sys.stderr.write('ERROR[Daemon]: Failed to load e-mail body template; %s\n' % str(e))

                    # ... create e-mail object
                    sSubject = 'Processing Results (%s, %s)' % (sUsername, strftime('%Y-%m-%dT%H:%M:%SZ', gmtime()))

                    # ... send to administrator
                    if self._sEmailAdmin:
                        try:
                            self._sendmail(self._sEmailSender, self._sEmailAdmin, self._sEmailSubjectPrefix+sSubject, sOutput)
                            if self._bDebug:
                                sys.stderr.write('DEBUG[Daemon]: Successfully sent token processing output to administrator; %s\n' % self._sEmailAdmin)
                        except Exception as e:
                            iErrorToken += 1
                            sys.stderr.write('ERROR[Daemon]: Failed to send token processing output to administrator; %s\n' % str(e))

                    # ... send to user
                    if self._bEmailUser:
                        sEmailUser = None

                        if self._bEmailUserAddressFromLdap:
                            # ... use ldap-stored e-mail address
                            try:

                                # ... initialize connection
                                try:
                                    oLdap = ldap.initialize(self._sLdapUri)
                                    oLdap.protocol_version = ldap.VERSION3
                                except Exception as e:
                                    raise RuntimeError('failed to initialize connection; %s' % str(e))

                                lLdapAttrList = [self._sLdapEmailAttribute]
                                if self._oLdapSearchScope == 'ldap.SCOPE_BASELEVEL':
                                    iLdapScope = ldap.SCOPE_BASELEVEL
                                elif self._oLdapSearchScope == 'ldap.SCOPE_ONELEVEL':
                                    iLdapScope = ldap.SCOPE_ONELEVEL
                                elif self._oLdapSearchScope == 'ldap.SCOPE_SUBTREE':
                                    iLdapScope = ldap.SCOPE_SUBTREE

                                # ... bind credentials
                                if self._sLdapBindPwd.startswith('file://'):
                                    sFile = self._sLdapBindPwd[7:]
                                    try:
                                        oFile = open(sFile, 'r', encoding=self._sLdapEncoding)
                                        sBindPwd = oFile.readline()
                                        oFile.close()
                                    except Exception as e:
                                        raise RuntimeError('failed to retrieve bind password from file; %s' % str(e))
                                else:
                                    sBindPwd = self._sLdapBindPwd

                                # ... bind to server
                                try:
                                    oLdap.bind_s(self._sLdapBindDN, sBindPwd, ldap.AUTH_SIMPLE)
                                except Exception as e:
                                    raise RuntimeError('failed to bind to server; %s' % str(e))

                                # ... retrieve user and its mail attribute
                                try:
                                    if not self._sLdapUserDN:
                                        lLdapResults = oLdap.search_ext_s(
                                            self._sLdapSearchDN,
                                            iLdapScope,
                                            self._sLdapSearchFilter.replace('%{USERNAME}', sUsername),
                                            lLdapAttrList,
                                            sizelimit=2
                                            )
                                    else:
                                        lLdapResults = oLdap.search_ext_s(
                                            self._sLdapUserDN.replace('%{USERNAME}', sUsername),
                                            ldap.SCOPE_BASE,
                                            '(objectClass=*)',
                                            lLdapAttrList,
                                            sizelimit=2
                                            )
                                    if not lLdapResults:
                                        raise RuntimeError('user not found: %s' % sUsername)
                                    elif len(lLdapResults) > 1:
                                        raise RuntimeError('too many match: %s' % sUsername)
                                    (sUserDn, dAttrs) = lLdapResults[0]
                                    sEmailUser = dAttrs[self._sLdapEmailAttribute][0].decode(self._sLdapEncoding)
                                except Exception as e:
                                    raise RuntimeError('failed to retrieve user mail attribute; %s' % str(e))

                                # ... unbind
                                try:
                                    oLdap.unbind_s()
                                except Exception as e:
                                    iErrorToken += 1
                                    sys.stderr.write('ERROR[Daemon]: Failed to unbind from LDAP server; %s\n' % str(e))

                            except Exception as e:
                                iErrorToken += 1
                                sys.stderr.write('ERROR[Daemon]: Failed to retrieve user e-mail address from LDAP server; %s\n' % str(e))

                        else:
                            # ... use user name as e-mail address
                            sEmailUser = sUsername
                            if self._sEmailUserDomain:
                                sEmailUser += '@'+self._sEmailUserDomain

                        # ... send the mail
                        if sEmailUser is not None:
                            try:
                                self._sendmail(self._sEmailSender, sEmailUser, self._sEmailSubjectPrefix+sSubject, sOutput)
                                if self._bDebug:
                                    sys.stderr.write('DEBUG[Daemon]: Successfully sent token processing output to user; %s\n' % sEmailUser)
                            except Exception as e:
                                iErrorToken += 1
                                sys.stderr.write('ERROR[Daemon]: Failed to send token processing output to user; %s\n' % str(e))

                # ... move token to archive directory (or delete it)
                sFileToken_archive = None
                if self._sTokenDirArchives is not None:
                    sFileToken_archive = self._sTokenDirArchives.rstrip(os.sep)+os.sep+os.path.basename(sFileToken)
                if sFileToken_archive is not None:
                    try:
                        shutil.move(sFileToken, sFileToken_archive)
                        if self._bDebug:
                            sys.stderr.write('DEBUG[Daemon]: Successfully moved token to archive directory; %s\n' % sFileToken_archive)
                    except Exception as e:
                        iErrorToken += 1
                        sys.stderr.write('ERROR[Daemon]: Failed to move token to archive directory; %s\n' % str(e))
                        sFileToken_archive = None
                if sFileToken_archive is None:
                    try:
                        os.remove(sFileToken)
                        if self._bDebug:
                            sys.stderr.write('DEBUG[Daemon]: Successfully deleted token file; %s\n' % sFileToken)
                    except Exception as e:
                        iErrorToken += 1
                        sys.stderr.write('ERROR[Daemon]: Failed to delete token file; %s\n' % str(e))

                # ... done (processing token)
                if iErrorToken:
                    iErrorTokens += 1

            # Done (processing tokens)
            if iErrorTokens:
                iError += 1
            elif iError:
                iError -= 1

            # Update incoming tokens directory last modification time (after tokens removal)
            try:
                fDirTokensMTime_1 = os.stat(self._sTokenDirPrivate).st_mtime
            except Exception as e:
                iError += 1
                sys.stderr.write('ERROR[Daemon]: Failed to retrieve tokens directory last modification time; %s\n' % str(e))
                fDirTokensMTime_1 = fDirTokensMTime_2

        # Done
        return 0


class DaemonLogger:
    """
    Universal Password Changer Token Processing Daemon Logger
    """

    #------------------------------------------------------------------------------
    # CONSTRUCTORS / DESTRUCTOR
    #------------------------------------------------------------------------------

    def __init__(self, _fnLog):
        # Fields
        self.__fnLog = _fnLog
        self.__sBuffer = ''


    #------------------------------------------------------------------------------
    # METHODS
    #------------------------------------------------------------------------------

    def flush(self):
        if self.__sBuffer:
            self.__fnLog(self.__sBuffer)
            self.__sBuffer = ''

    def write(self, _s):
        while _s:
            i = _s.find('\n')
            if i < 0:
                self.__sBuffer += _s
                break
            self.__sBuffer += _s[:i]
            if self.__sBuffer:
                self.__fnLog(self.__sBuffer)
                self.__sBuffer = ''
            _s = _s[i+1:]


    def writelines(self, _lsLines):
        for sLine in _lsLines:
            self.write(sLine)


class DaemonMain(Daemon):
    """
    Universal Password Changer Token Processing Daemon Main Executable
    """

    #------------------------------------------------------------------------------
    # CONSTRUCTORS / DESTRUCTOR
    #------------------------------------------------------------------------------

    def __init__(self):
        Daemon.__init__(self)

        # Fields
        self.__oArgumentParser = None
        self.__oArguments = None
        self.__oConfigObj = None

        # Initialization
        self.__initArgumentParser()


    def __initArgumentParser(self):
        """
        Creates the arguments parser (and help generator)
        """

        # Create argument parser
        self.__oArgumentParser = AP.ArgumentParser(sys.argv[0].split(os.sep)[-1])

        # ... configuration file
        self.__oArgumentParser.add_argument(
            '-C', '--config', type=str,
            metavar='<conf-file>',
            default='/etc/upwdchg/daemon/upwdchg-daemon.conf',
            help='Path to configuration file (default:/etc/upwdchg/daemon/upwdchg-daemon.conf)')

        # ... PID file
        self.__oArgumentParser.add_argument(
            '-p', '--pid', type=str,
            metavar='<pid-file>',
            default='/var/run/upwdchg-daemon.pid',
            help='Path to daemon PID file (default:/var/run/upwdchg-daemon.pid)')

        # ... remain in foreground
        self.__oArgumentParser.add_argument(
            '-f', '--foreground', action='store_true',
            default=False,
            help='Do not fork to background / Remain on foreground')

        # ... debug
        self.__oArgumentParser.add_argument(
            '-d', '--debug', action='store_true',
            default=False,
            help='Enable debugging messages')

        # ... show configuration
        self.__oArgumentParser.add_argument(
            '--showconf', type=str,
            metavar='<configobj.path>',
            default=None,
            help='Show configuration and exit')

        # ... version
        self.__oArgumentParser.add_argument(
            '-v', '--version', action='version',
            version=('UPwdChg - %s - Cedric Dufour <http://cedric.dufour.name>\n' % UPWDCHG_VERSION))


    def __initArguments(self, _aArguments = None):
        """
        Parses the command-line arguments; returns a non-zero exit code in case of failure.
        """

        # Parse arguments
        if _aArguments is None: _aArguments = sys.argv
        try:
            self.__oArguments = self.__oArgumentParser.parse_args()
        except Exception as e:
            self.__oArguments = None
            sys.stderr.write('ERROR[DaemonMain]: Failed to parse arguments; %s\n' % str(e))
            return 1

        return 0


    def __initConfigObj(self):
        """
        Loads configuration settings; returns a non-zero exit code in case of failure.
        """

        # Load configuration settings
        try:
            self.__oConfigObj = CO.ConfigObj(
                self.__oArguments.config,
                configspec=UPWDCHG_DAEMON_CONFIGSPEC,
                file_error=True)
        except Exception as e:
            self.__oConfigObj = None
            sys.stderr.write('ERROR[DaemonMain]: Failed to load configuration from file; %s\n' % str(e))
            return 1

        # ... and validate it
        oValidator = VA.Validator()
        oValidatorResult = self.__oConfigObj.validate(oValidator)
        if oValidatorResult != True:
            sys.stderr.write('ERROR[Daemon]: Invalid configuration data\n')
            for(lSectionList, sKey, _) in CO.flatten_errors(self.__oConfigObj, oValidatorResult):
                if sKey is not None:
                    sys.stderr.write(' > Invalid value/pair (%s:%s)\n' % (', '.join(lSectionList), sKey))
                else:
                    sys.stderr.write(' > Missing/incomplete section (%s)\n' % ', '.join(lSectionList))
            return 1

        return 0

    def __writeConfigObj(self, _sPath=None, _dConfig=None, _sPrefix=None):
        """
        Write configuration settings (to stdout, in a shell-friendly way).
        """

        if not _dConfig:
            _dConfig = self.__oConfigObj
        if not _sPath:
            lKeys = list(_dConfig.keys())
        else:
            lPath = _sPath.split('.')
            sKey = lPath[0].replace('*', '')
            lKeys = [sKey] if sKey else list(_dConfig.keys())
            _sPath = '.'.join(lPath[1:])
        for sKey in lKeys:
            if sKey not in _dConfig.keys():
                continue
            if isinstance(_dConfig[sKey], dict):
                self.__writeConfigObj(_sPath, _dConfig[sKey], sKey)
            else:
                sName = _sPrefix+'_'+sKey if _sPrefix else sKey
                sValue = _dConfig[sKey]
                if sValue is None:
                    sValue = ''
                elif isinstance(sValue, bool):
                    sValue = '1' if sValue else '0'
                elif isinstance(sValue, str):
                    sValue = "'%s'" % sValue
                sys.stdout.write('%s=%s\n' % (sName, sValue))


    #------------------------------------------------------------------------------
    # METHODS
    #------------------------------------------------------------------------------

    def __syslog(self, _sMessage):
        iLevel = syslog.LOG_INFO
        if _sMessage.find('ERROR') >= 0:
            iLevel = syslog.LOG_ERR
        elif _sMessage.find('WARNING') >= 0:
            iLevel = syslog.LOG_WARNING
        elif _sMessage.find('DEBUG') >= 0:
            iLevel = syslog.LOG_DEBUG
        syslog.syslog(iLevel, _sMessage)


    def __daemon(self):
        """
        Daemonizes the process; returns a non-zero exit code in case of failure.
        """

        # Daemonize
        try:
            # Create and check PID file
            oPidLockFile = make_pidlockfile(self.__oArguments.pid, 0)
            if is_pidfile_stale(oPidLockFile):
                oPidLockFile.break_lock()
            if oPidLockFile.is_locked():
                sys.stderr.write('ERROR[DaemonMain]: Daemon process already running; PID=%s\n' % oPidLockFile.read_pid())
                return 1

            # Create daemon context
            oDaemonContext = DaemonContext(pidfile=oPidLockFile)
            oDaemonContext.signal_map = { signal.SIGTERM: self._signal }
            oDaemonContext.open()
            emit_message('[%s]' % os.getpid())

            # Redirect standard error to syslog
            syslog.openlog('upwdchg-daemon', syslog.LOG_PID, syslog.LOG_DAEMON)
            sys.stderr = DaemonLogger(self.__syslog)

            # Execute
            return self.processTokens()
        except Exception as e:
            sys.stderr.write('ERROR[DaemonMain]: Failed to fork to background; %s\n' % str(e))
            return 1


    def execute(self):
        """
        Executes; returns a non-zero exit code in case of failure.
        """

        # Initialize

        # ... arguments
        iReturn = self.__initArguments()
        if iReturn:
            return iReturn

        # ... configuration
        iReturn = self.__initConfigObj()
        if iReturn: return iReturn

        # Show configuration (?)
        if self.__oArguments.showconf is not None:
            self.__writeConfigObj(self.__oArguments.showconf)
            return 0

        # Configure daemon
        self._bDebug = self.__oArguments.debug
        self._sTokenDirPrivate = self.__oConfigObj['token']['private_directory']
        self._sTokenFileKeyPrivate = self.__oConfigObj['token']['private_key_file']
        self._sTokenDirPublic = self.__oConfigObj['token']['public_directory']
        self._sTokenFileKeyPublic = self.__oConfigObj['token']['public_key_file']
        self._sTokenDirPlugins = self.__oConfigObj['token']['plugins_directory']
        self._sTokenFileRandom = self.__oConfigObj['token']['random_file']
        self._sTokenAllowedTypes = self.__oConfigObj['token']['allowed_types']
        self._sTokenDirArchives = self.__oConfigObj['token']['archive_directory']
        self._fProcessInterval = self.__oConfigObj['process']['interval']
        self._iProcessMaxTokens = self.__oConfigObj['process']['max_tokens']
        self._iProcessMaxErrors = self.__oConfigObj['process']['max_errors']
        self._sEmailAdmin = self.__oConfigObj['email']['admin_address']
        self._bEmailUser = self.__oConfigObj['email']['user_send']
        self._sEmailUserDomain = self.__oConfigObj['email']['user_domain']
        self._bEmailUserAddressFromLdap = self.__oConfigObj['email']['user_address_from_ldap']
        self._sEmailSender = self.__oConfigObj['email']['sender_address']
        self._sEmailSubjectPrefix = self.__oConfigObj['email']['subject_prefix']
        self._sEmailFileBodyTemplate = self.__oConfigObj['email']['body_template_file']
        self._sEmailSendmail = self.__oConfigObj['email']['sendmail_binary']
        self._sEmailEncoding = self.__oConfigObj['email']['encoding']
        self._sLdapUri = self.__oConfigObj['ldap']['uri']
        self._sLdapBindDN = self.__oConfigObj['ldap']['bind_dn']
        self._sLdapBindPwd = self.__oConfigObj['ldap']['bind_pwd']
        self._sLdapUserDN = self.__oConfigObj['ldap']['user_dn']
        self._sLdapSearchDN = self.__oConfigObj['ldap']['search_dn']
        self._oLdapSearchScope = self.__oConfigObj['ldap']['search_scope']
        self._sLdapSearchFilter = self.__oConfigObj['ldap']['search_filter']
        self._sLdapEmailAttribute = self.__oConfigObj['ldap']['email_attribute']
        self._sLdapEncoding = self.__oConfigObj['ldap']['encoding']

        # Check dependencies
        if self._bEmailUser and self._bEmailUserAddressFromLdap and not LDAP_AVAILABLE:
            sys.stderr.write('ERROR[DaemonMain]: Missing LDAP dependency\n')
            return 1

        # Fork to background (?)
        if not self.__oArguments.foreground:
            return self.__daemon()

        # Foreground processing
        signal.signal(signal.SIGINT, self._signal)
        signal.signal(signal.SIGTERM, self._signal)
        return self.processTokens()

        # Done
        return 0
