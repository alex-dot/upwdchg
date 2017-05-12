#!/usr/bin/env python
# -*- mode:python; tab-width:4; c-basic-offset:4; intent-tabs-mode:nil; -*-
# ex: filetype=python tabstop=4 softtabstop=4 shiftwidth=4 expandtab autoindent smartindent

#
# Universal Password Changer (UPwdChg)
# Copyright (C) 2014 Cedric Dufour <http://cedric.dufour.name>
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

# Modules
# ... deb: python-argparse, python-configobj, python-daemon, python-ldap
from UPwdChg import \
    UPWDCHG_VERSION, \
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
import signal
from subprocess import \
    Popen, \
    PIPE
import os
import stat
import sys
import syslog
import time
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
        self._sDirArchives = None
        self._sEmailAdmin = None
        self._bEmailUser = False
        self._sEmailUserDomain = None
        self._bEmailUserAddressFromLdap = False
        self._sEmailSender = 'upwdchg-daemon'
        self._uEmailSubjectPrefix = u'[UPWDCHG] '
        self._sFileEmailBodyTemplate = None
        self._sEmailSendmail = 'sendmail'
        self._sLdapUri = 'ldap://ldap.example.org:389'
        self._sLdapBindDN = 'cn=admin,dc=example,dc=org'
        self._sLdapBindPwd = ''
        self._sLdapSearchDN = 'ou=users,dc=example,dc=org'
        self._oLdapSearchScope = 'ldap.SCOPE_ONELEVEL'
        self._sLdapSearchFilter = '(&(objectClass=posixAccount)(uid=%{USERNAME}))'
        self._sLdapEmailAttribute = 'mail'


    #------------------------------------------------------------------------------
    # METHODS
    #------------------------------------------------------------------------------

    def _signal(self, signal, frame):
        self.__bInterrupted = True


    def processTokens(self, _sDirTokens, _sFilePrivateKey, _sDirPlugins, _fInterval, _iErrorsMax = None):
        """
        Watch directory for tokens and process them; returns a non-zero exit code in case of failure.
        """

        # Check tokens directory
        if not os.path.isdir(_sDirTokens):
            sys.stderr.write('ERROR[Daemon]: Invalid tokens directory\n')
            return 1
        fDirTokensMTime_1 = 0.0

        # Processing object
        oProcess = Process()

        # Loop
        iError = 0
        while True:
            # Check loop conditions
            if self.__bInterrupted:
                break
            if _iErrorsMax and iError >= _iErrorsMax:
                if self._bDebug:
                    sys.stderr.write('DEBUG[Daemon]: Too-many errors; bailing out\n')
                return 1

            # Check tokens directory for changes
            try:
                fDirTokensMTime_2 = os.stat(_sDirTokens).st_mtime
            except Exception as e:
                iError += 1
                sys.stderr.write('ERROR[Daemon]: Failed to retrieve tokens directory last modification time; %s\n' % str(e))
                fDirTokensMTime_2 = fDirTokensMTime_1
            if (fDirTokensMTime_2 - fDirTokensMTime_1) < 0.1:
                if self._bDebug:
                    sys.stderr.write('DEBUG[Daemon]: Sleeping for %f seconds...\n' % _fInterval)
                time.sleep(_fInterval)
                continue
            if self._bDebug:
                sys.stderr.write('DEBUG[Daemon]: Detected changes in tokens directory\n')

            # List tokens
            lsFilesToken = list()
            if _sDirTokens is not None:
                try:
                    for sFile in os.listdir(_sDirTokens):
                        sFile = _sDirTokens.rstrip(os.sep)+os.sep+sFile
                        if os.path.isfile(sFile):
                            lsFilesToken.append(sFile)
                except Exception as e:
                    iError += 1
                    sys.stderr.write('ERROR[Daemon]: Failed to retrieve tokens list; %s\n' % str(e))
                    continue
            if not len(lsFilesToken):
                if fDirTokensMTime_1:
                    sys.stderr.write('WARNING[Daemon]: No password change token found\n')
                fDirTokensMTime_1 = fDirTokensMTime_2
                continue
            lsFilesToken.sort()

            # Update tokens directory last modification time
            fDirTokensMTime_1 = fDirTokensMTime_2

            # List plugins
            lsFilesPlugin = oProcess.getPlugins(_sDirPlugins)
            if lsFilesPlugin is None:
                iError += 1
                sys.stderr.write('ERROR[Daemon]: No processing plugin found\n')
                continue
            if self._bDebug:
                for sFilePlugin in lsFilesPlugin:
                    sys.stderr.write('DEBUG[Daemon]: Token processing plugin; %s\n' % sFilePlugin)


            # Process tokens
            iErrorTokens = 0
            for sFileToken in lsFilesToken:
                iErrorToken = 0
                sys.stderr.write('INFO[Daemon]: Processing token; %s\n' % sFileToken)

                # ... process token
                lsOutputs = oProcess.processToken(sFileToken, _sFilePrivateKey, lsFilesPlugin)
                if lsOutputs is None:
                    iErrorToken += 1
                    sys.stderr.write('ERROR[Daemon]: Token processing returned no output\n')

                # ... process output
                if lsOutputs and (self._sEmailAdmin or self._bEmailUser):
                    sOutput = ''.join(lsOutputs)

                    # ... retrieve token username
                    sUsername = 'UNKNOWN'
                    oToken = TokenReader()
                    if oToken.read(sFileToken, _sFilePrivateKey):
                        iErrorToken += 1
                        sys.stderr.write('ERROR[Daemon]: Token processing returned no output\n')
                    else:
                        sUsername = oToken.getData()['username'].encode('utf-8')

                    # ... e-mail body template
                    if self._sFileEmailBodyTemplate:
                        try:
                            oFile = open(self._sFileEmailBodyTemplate, 'r', 'utf-8')
                            sOutput = (''.join(oFile.readlines())).replace('%{OUTPUT}', sOutput)
                            oFile.close()
                        except Exception as e:
                            iErrorToken += 1
                            sys.stderr.write('ERROR[Daemon]: Failed to load e-mail body template; %s\n' % str(e))

                    # ... create e-mail object
                    sSubject = 'Password change results (%s, %s)' % (sUsername, time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))

                    # ... send to administrator
                    if self._sEmailAdmin:
                        try:
                            oMIMEText = MIMEText(sOutput, 'plain', 'utf-8')
                            oMIMEText['From'] = self._sEmailSender
                            oMIMEText['Subject'] = self._uEmailSubjectPrefix.encode('utf-8')+sSubject
                            oMIMEText['To'] = self._sEmailAdmin
                            oPopen = Popen([ self._sEmailSendmail, '-t' ], stdin=PIPE)
                            oPopen.communicate(oMIMEText.as_string())
                        except Exception, e:
                            iErrorToken += 1
                            sys.stderr.write('ERROR[Daemon]: Failed to send token processing output to administrator; %s\n' % str(e))

                    # ... send to user
                    if self._bEmailUser:
                        sEmailUser = None

                        if self._bEmailUserAddressFromLdap:
                            # ... use ldap-stored e-mail address
                            try:

                                lLdapAttrList = [self._sLdapEmailAttribute]
                                if self._oLdapSearchScope == 'ldap.SCOPE_BASELEVEL':
                                    iLdapScope = ldap.SCOPE_BASELEVEL
                                elif self._oLdapSearchScope == 'ldap.SCOPE_ONELEVEL':
                                    iLdapScope = ldap.SCOPE_ONELEVEL
                                elif self._oLdapSearchScope == 'ldap.SCOPE_SUBTREE':
                                    iLdapScope = ldap.SCOPE_SUBTREE

                                if self._sLdapBindPwd.startswith('file://'):
                                    sFile = self._sLdapBindPwd[7:]
                                    try:
                                        oFile = open(sFile, 'r')
                                        sBindPwd = oFile.readline()
                                        oFile.close()
                                    except Exception as e:
                                        raise Exception('failed to retrieve bind password from file; %s' % str(e))
                                else:
                                    sBindPwd = self._sLdapBindPwd

                                # ... bind
                                try:
                                    oLdap = ldap.initialize(self._sLdapUri)
                                    oLdap.protocol_version = ldap.VERSION3
                                    oLdap.bind_s(self._sLdapBindDN, sBindPwd, ldap.AUTH_SIMPLE)
                                except Exception as e:
                                    raise Exception('failed to bind to server; %s' % str(e))

                                # ... search
                                try:
                                    lLdapResults = oLdap.search_ext_s(
                                        self._sLdapSearchDN,
                                        iLdapScope,
                                        self._sLdapSearchFilter.replace('%{USERNAME}', sUsername),
                                        lLdapAttrList,
                                        sizelimit=2
                                        )
                                    if not lLdapResults:
                                        raise Exception('user not found: %s' % sUsername)
                                    elif len(lLdapResults) > 1:
                                        raise Exception('too many match: %s' % sUsername)
                                    (sUserDn, dAttrs) = lLdapResults[0]
                                    sEmailUser = dAttrs[self._sLdapEmailAttribute][0]
                                except Exception as e:
                                    raise Exception('failed to perform user search; %s' % str(e))

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
                                oMIMEText = MIMEText(sOutput, 'plain', 'utf-8')
                                oMIMEText['From'] = self._sEmailSender
                                oMIMEText['Subject'] = self._uEmailSubjectPrefix.encode('utf-8')+sSubject
                                oMIMEText['To'] = sEmailUser
                                oPopen = Popen([ self._sEmailSendmail, '-t' ], stdin=PIPE)
                                oPopen.communicate(oMIMEText.as_string())
                            except Exception, e:
                                iErrorToken += 1
                                sys.stderr.write('ERROR[Daemon]: Failed to send token processing output to user; %s\n' % str(e))

                # ... move token to archive directory (or delete it)
                sFileToken_archive = None
                if self._sDirArchives is not None:
                    sFileToken_archive = self._sDirArchives.rstrip(os.sep)+os.sep+os.path.basename(sFileToken)
                if sFileToken_archive is not None:
                    try:
                        shutil.move(sFileToken, sFileToken_archive)
                    except Exception as e:
                        iErrorToken += 1
                        sys.stderr.write('ERROR[Daemon]: Failed to move token to archive directory; %s\n' % str(e))
                        sFileToken_archive = None
                if sFileToken_archive is None:
                    try:
                        os.remove(sFileToken)
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

            # Update tokens directory last modification time (after tokens removal)
            try:
                fDirTokensMTime_1 = os.stat(_sDirTokens).st_mtime
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
        except Exception, e:
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
        except Exception, e:
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
            return self.processTokens(
                self.__oConfigObj['token']['pending_directory'],
                self.__oConfigObj['token']['private_key_file'],
                self.__oConfigObj['token']['plugins_directory'],
                self.__oConfigObj['process']['interval'],
                self.__oConfigObj['process']['max_errors'],
                )
        except Exception, e:
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

        # Configure daemon
        self._bDebug = self.__oArguments.debug
        self._sDirArchives = self.__oConfigObj['token']['archive_directory']
        self._sEmailAdmin = self.__oConfigObj['email']['admin_address']
        self._bEmailUser = self.__oConfigObj['email']['user_send']
        self._sEmailUserDomain = self.__oConfigObj['email']['user_domain']
        self._bEmailUserAddressFromLdap = self.__oConfigObj['email']['user_address_from_ldap']
        self._sEmailSender = self.__oConfigObj['email']['sender_address']
        self._uEmailSubjectPrefix = self.__oConfigObj['email']['subject_prefix']
        self._sFileEmailBodyTemplate = self.__oConfigObj['email']['body_template_file']
        self._sEmailSendmail = self.__oConfigObj['email']['sendmail_binary']
        self._sLdapUri = self.__oConfigObj['ldap']['uri']
        self._sLdapBindDN = self.__oConfigObj['ldap']['bind_dn']
        self._sLdapBindPwd = self.__oConfigObj['ldap']['bind_pwd']
        self._sLdapSearchDN = self.__oConfigObj['ldap']['search_dn']
        self._oLdapSearchScope = self.__oConfigObj['ldap']['search_scope']
        self._sLdapSearchFilter = self.__oConfigObj['ldap']['search_filter']
        self._sLdapEmailAttribute = self.__oConfigObj['ldap']['email_attribute']

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
        return self.processTokens(
            self.__oConfigObj['token']['pending_directory'],
            self.__oConfigObj['token']['private_key_file'],
            self.__oConfigObj['token']['plugins_directory'],
            self.__oConfigObj['process']['interval'],
            self.__oConfigObj['process']['max_errors'],
            )

        # Done
        return 0
