#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : SMBSession.py
# Author             : Remi Gascou (@podalirius_)
# Date created       : 12 Aug 2025


from __future__ import annotations

import ntpath
import re
import traceback
from typing import TYPE_CHECKING, Optional

from impacket.dcerpc.v5 import rpcrt, rrp, srvs, transport
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.ldap import ldaptypes
from impacket.smb3structs import (DACL_SECURITY_INFORMATION,
                                  FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE,
                                  FILE_OPEN, FILE_READ_ATTRIBUTES,
                                  GROUP_SECURITY_INFORMATION,
                                  OWNER_SECURITY_INFORMATION, READ_CONTROL,
                                  SMB2_0_INFO_SECURITY, SMB2_SEC_INFO_00,
                                  SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30)
from impacket.smbconnection import SessionError, SMBConnection
from impacket.smb import SMB_DIALECT

from sharehound.core.SIDResolver import SIDResolver
from sharehound.utils.utils import STYPE_MASK, is_port_open


class SMBErrorClassifier:
    """Classifies SMB errors into categories for better handling and logging."""
    
    # Common SMB/NT Status codes
    STATUS_NOT_SUPPORTED = 0xc00000bb
    STATUS_ACCESS_DENIED = 0xc0000022
    STATUS_LOGON_FAILURE = 0xc000006d
    STATUS_ACCOUNT_DISABLED = 0xc0000072
    STATUS_ACCOUNT_LOCKED_OUT = 0xc0000234
    STATUS_PASSWORD_EXPIRED = 0xc0000071
    STATUS_INVALID_LOGON_HOURS = 0xc000006f
    STATUS_INVALID_WORKSTATION = 0xc0000070
    STATUS_ACCOUNT_RESTRICTION = 0xc000006e
    STATUS_BAD_NETWORK_NAME = 0xc00000cc
    STATUS_CONNECTION_REFUSED = 0xc0000236
    STATUS_NETWORK_UNREACHABLE = 0xc000023c
    STATUS_HOST_UNREACHABLE = 0xc000023d
    
    @classmethod
    def classify(cls, error: SessionError) -> tuple[str, str, bool]:
        """
        Classify an SMB SessionError.
        
        Returns:
            tuple: (category, message, should_retry_with_different_dialect)
        """
        error_code = error.getErrorCode()
        
        # Protocol/dialect issues - retry with different dialect
        if error_code == cls.STATUS_NOT_SUPPORTED:
            return ("PROTOCOL", "SMB dialect or feature not supported by server", True)
        
        # Authentication failures - don't retry
        if error_code == cls.STATUS_LOGON_FAILURE:
            return ("AUTH", "Invalid username or password", False)
        if error_code == cls.STATUS_ACCESS_DENIED:
            return ("AUTH", "Access denied - insufficient privileges", False)
        if error_code == cls.STATUS_ACCOUNT_DISABLED:
            return ("AUTH", "Account is disabled", False)
        if error_code == cls.STATUS_ACCOUNT_LOCKED_OUT:
            return ("AUTH", "Account is locked out", False)
        if error_code == cls.STATUS_PASSWORD_EXPIRED:
            return ("AUTH", "Password has expired", False)
        if error_code == cls.STATUS_INVALID_LOGON_HOURS:
            return ("AUTH", "Login outside allowed hours", False)
        if error_code == cls.STATUS_INVALID_WORKSTATION:
            return ("AUTH", "Login from this workstation not allowed", False)
        if error_code == cls.STATUS_ACCOUNT_RESTRICTION:
            return ("AUTH", "Account restriction preventing login", False)
        
        # Network issues - don't retry with different dialect
        if error_code == cls.STATUS_BAD_NETWORK_NAME:
            return ("NETWORK", "Share or network name not found", False)
        if error_code in (cls.STATUS_CONNECTION_REFUSED, cls.STATUS_NETWORK_UNREACHABLE, cls.STATUS_HOST_UNREACHABLE):
            return ("NETWORK", "Network connectivity issue", False)
        
        # Unknown - might be worth retrying
        return ("UNKNOWN", str(error), True)

if TYPE_CHECKING:
    from impacket.smb import SharedFile

    from sharehound.core.Config import Config
    from sharehound.core.Credentials import Credentials
    from sharehound.core.Logger import Logger


class SMBSession(object):
    """
    Represents an SMB session for interacting with an SMB server.

    This class provides methods to manage and interact with an SMB server, including
    connecting to the server, listing shares, uploading and downloading files, and
    managing directories and files on the server. It handles session initialization,
    authentication, and cleanup.

    Attributes:
        host (str): The hostname or IP address of the SMB server.
        port (int): The port number on which the SMB server is listening.
        credentials (dict): Authentication credentials for the SMB server.
        config (dict, optional): Configuration options for the SMB session.
        smbClient (impacket.smbconnection.SMBConnection): The SMB connection instance.
        connected (bool): Connection status to the SMB server.
        available_shares (dict): A dictionary of available SMB shares.
        smb_share (str): The current SMB share in use.
        smb_cwd (str): The current working directory on the SMB share.
        smb_tree_id (int): The tree ID of the connected SMB share.

    Methods:
        close_smb_session(): Closes the current SMB session.
        init_smb_session(): Initializes the SMB session with the server.
        list_shares(): Lists all shares available on the SMB server.
        set_share(shareName): Sets the current SMB share.
        set_cwd(path): Sets the current working directory on the SMB share.
        put_file(localpath): Uploads a file to the current SMB share.
        get_file(remotepath, localpath): Downloads a file from the SMB share.
        mkdir(path): Creates a directory on the SMB share.
        rmdir(path): Removes a directory from the SMB share.
        rm(path): Removes a file from the SMB share.
        read_file(path): Reads a file from the SMB share.
        test_rights(sharename): Tests read and write access rights on a share.
    """

    config: Config
    logger: Logger
    host: str
    remote_name: str
    port: int
    timeout: int
    advertisedName: Optional[str]

    # Credentials
    credentials: Credentials

    smbClient: Optional[SMBConnection] = None
    connected: bool = False

    available_shares: dict[str, dict] = {}
    smb_share: Optional[str] = None
    smb_cwd: str = ""
    smb_tree_id: Optional[int] = None

    dce_srvsvc: Optional[rpcrt.DCERPC_v5] = None
    sid_resolver: SIDResolver

    def __init__(
        self,
        host,
        port,
        timeout,
        credentials,
        remote_name=None,
        advertisedName=None,
        config=None,
        logger=None,
    ):
        super(SMBSession, self).__init__()
        # Objects
        self.config = config
        self.logger = logger

        # Target server
        self.host = host
        self.remote_name = remote_name or host
        # Target port (by default on 445)
        self.port = port
        # Timeout (default 3 seconds)
        self.timeout = timeout
        self.advertisedName = advertisedName

        # Credentials
        self.credentials = credentials

        self.list_shares()

    # Connect and disconnect SMB session

    def close_smb_session(self):
        """
        Closes the current SMB session by disconnecting the SMB client.

        This method ensures that the SMB client connection is properly closed. It checks if the client is connected
        and if so, it closes the connection and resets the connection status.

        Raises:
            Exception: If the SMB client is not initialized or if there's an error during the disconnection process.
        """

        if self.smbClient is not None:
            if self.connected:
                self.smbClient.close()
                self.connected = False
                self.logger.debug("[+] SMB connection closed successfully.")
            else:
                self.logger.debug("[!] No active SMB connection to close.")
        else:
            raise Exception("SMB client is not initialized.")

    def init_smb_session(self) -> bool:
        """
        Initializes and establishes a session with the SMB server.

        This method sets up the SMB connection using either Kerberos or NTLM authentication based on the configuration.
        It attempts to connect to the SMB server specified by the `address` attribute and authenticate using the credentials provided during the object's initialization.
        
        If the initial connection fails with STATUS_NOT_SUPPORTED, it will automatically retry with older SMB dialects
        (SMB3 -> SMB2.1 -> SMB2 -> SMB1) to maximize compatibility with different server configurations.

        The method will print debug information if the `debug` attribute is set to True. Upon successful connection and authentication, it sets the `connected` attribute to True.

        Returns:
            bool: True if the connection and authentication are successful, False otherwise.
        """

        self.connected = False

        self.logger.debug(
            "[>] Connecting to remote SMB server '%s' ... " % str(self.host)
        )

        # Check if port is open first
        result, error = is_port_open(self.host, self.port, self.timeout)
        if not result:
            self.logger.debug(
                f"Could not connect to '{self.host}:{self.port}', {error}."
            )
            self.connected = False
            return False

        # Define dialects to try in order of preference (newest to oldest)
        # None means let impacket negotiate automatically
        dialects_to_try = [
            (None, "auto-negotiate"),
            (SMB2_DIALECT_30, "SMB 3.0"),
            (SMB2_DIALECT_21, "SMB 2.1"),
            (SMB2_DIALECT_002, "SMB 2.0"),
            (SMB_DIALECT, "SMB 1.0"),
        ]

        last_error = None
        last_error_category = None
        
        for dialect, dialect_name in dialects_to_try:
            try:
                self.logger.debug(f"[>] Trying connection with {dialect_name}...")
                
                # Create SMB connection with specific dialect
                if dialect is None:
                    self.smbClient = SMBConnection(
                        remoteName=self.remote_name,
                        remoteHost=self.host,
                        myName=self.advertisedName,
                        sess_port=int(self.port),
                        timeout=self.timeout,
                    )
                else:
                    self.smbClient = SMBConnection(
                        remoteName=self.remote_name,
                        remoteHost=self.host,
                        myName=self.advertisedName,
                        sess_port=int(self.port),
                        timeout=self.timeout,
                        preferredDialect=dialect,
                    )
                
                # Try to authenticate
                auth_result = self._authenticate()
                
                if auth_result:
                    self.connected = True
                    self.logger.debug(
                        f"[+] Successfully authenticated to '{self.host}' as '{self.credentials.domain}\\{self.credentials.username}' using {dialect_name}!"
                    )
                    break
                else:
                    # Authentication failed but connection worked - don't retry with different dialect
                    self.logger.debug(
                        f"Authentication failed to '{self.host}' as '{self.credentials.domain}\\{self.credentials.username}'"
                    )
                    self.connected = False
                    return False
                    
            except SessionError as err:
                category, message, should_retry = SMBErrorClassifier.classify(err)
                last_error = err
                last_error_category = category
                
                self.logger.debug(f"[{category}] {dialect_name} failed: {message}")
                
                if not should_retry:
                    # Don't retry for auth failures or network issues
                    self.logger.debug(f"Not retrying due to {category} error")
                    self.connected = False
                    return False
                    
                # Close the failed connection before retrying
                if self.smbClient is not None:
                    try:
                        self.smbClient.close()
                    except Exception:
                        pass
                    self.smbClient = None
                    
                # Continue to try next dialect
                continue
                
            except OSError as err:
                if self.config.debug:
                    traceback.print_exc()
                self.logger.debug(
                    f"[NETWORK] Could not connect to '{self.host}:{self.port}': {err}"
                )
                self.connected = False
                return False
            
            except Exception as err:
                if self.config.debug:
                    traceback.print_exc()
                self.logger.debug(f"[ERROR] Unexpected error with {dialect_name}: {err}")
                
                # Close and try next dialect
                if self.smbClient is not None:
                    try:
                        self.smbClient.close()
                    except Exception:
                        pass
                    self.smbClient = None
                continue

        # If we exhausted all dialects without success
        if not self.connected:
            if last_error:
                self.logger.debug(
                    f"Failed to connect to '{self.host}' after trying all SMB dialects. Last error [{last_error_category}]: {last_error}"
                )
            else:
                self.logger.debug(
                    f"Failed to connect to '{self.host}' - unknown error"
                )
            return False

        # Initialize additional services if connected
        if self.connected:
            try:
                self.sid_resolver = SIDResolver(self.smbClient)
            except Exception as err:
                self.logger.debug(f"SIDResolver could not be initialized: {err}")
            try:
                rpctransport = transport.SMBTransport(
                    self.smbClient.getRemoteName(),
                    self.smbClient.getRemoteHost(),
                    filename=r"\srvsvc",
                    smb_connection=self.smbClient,
                )
                self.dce_srvsvc = rpctransport.get_dce_rpc()
                self.dce_srvsvc.connect()
                self.dce_srvsvc.bind(srvs.MSRPC_UUID_SRVS)
            except Exception as err:
                self.logger.debug(f"Could not initialize connection to srvsvc: {err}")

        return self.connected

    def _authenticate(self) -> bool:
        """
        Performs authentication against the SMB server.
        
        Returns:
            bool: True if authentication successful, False otherwise.
        """
        try:
            if self.credentials.use_kerberos:
                self.logger.debug(
                    "[>] Authenticating as '%s\\%s' with kerberos ... "
                    % (self.credentials.domain, self.credentials.username)
                )
                return self.smbClient.kerberosLogin(
                    user=self.credentials.username,
                    password=self.credentials.password,
                    domain=self.credentials.domain,
                    lmhash=self.credentials.lm_hex,
                    nthash=self.credentials.nt_hex,
                    aesKey=self.credentials.aesKey,
                    kdcHost=self.credentials.kdcHost,
                )
            else:
                if len(self.credentials.lm_hex) != 0 and len(self.credentials.nt_hex) != 0:
                    self.logger.debug(
                        "[>] Authenticating as '%s\\%s' with NTLM pass-the-hash ... "
                        % (self.credentials.domain, self.credentials.username)
                    )
                else:
                    self.logger.debug(
                        "[>] Authenticating as '%s\\%s' with NTLM password ... "
                        % (self.credentials.domain, self.credentials.username)
                    )
                
                return self.smbClient.login(
                    user=self.credentials.username,
                    password=self.credentials.password,
                    domain=self.credentials.domain,
                    lmhash=self.credentials.lm_hex,
                    nthash=self.credentials.nt_hex,
                )
        except SessionError as err:
            # Re-raise to be handled by caller with dialect fallback logic
            raise

    def ping_smb_session(self) -> bool:
        """
        Tests the connectivity to the SMB server by sending an echo command.

        This method attempts to send an echo command to the SMB server to check if the session is still active.
        It updates the `connected` attribute of the class based on the success or failure of the echo command.

        Returns:
            bool: True if the echo command succeeds (indicating the session is active), False otherwise.
        """

        portIsOpen, error = is_port_open(self.host, self.port, self.timeout)
        if not portIsOpen:
            self.connected = False
        else:
            try:
                # Try to ping the SMB server to see if we timed out
                self.smbClient.getSMBServer().echo()
            except Exception:
                self.connected = False

        return self.connected

    # Operations

    def get_entry(self, path: Optional[str] = None) -> Optional[SharedFile]:
        """
        Retrieves information about a specific entry located at the provided path on the SMB share.

        This method checks if the specified path exists on the SMB share. If the path exists, it retrieves the details of the entry at that path, including the directory name and file name. If the entry is found, it returns the entry object; otherwise, it returns None.

        Args:
            path (str): The path of the entry to retrieve information about.

        Returns:
            Entry: An object representing the entry at the specified path, or None if the entry is not found.
        """

        if self.path_exists(path=path):
            matches = self.smbClient.listPath(shareName=self.smb_share, path=path)

            if len(matches) == 1:
                return matches[0]
            else:
                return None
        else:
            return None

    def get_entry_security_descriptor(
        self, path: str, entry: SharedFile
    ) -> Optional[ldaptypes.SR_SECURITY_DESCRIPTOR]:
        """
        Get the security descriptor of a file on the SMB share.

        Returns:
            str: The security descriptor of the file.
        """

        if self.smb_tree_id is None:
            self.logger.debug("SMB tree ID is not set, please set it first.")
            return None

        # Construct the full path to the specific file/directory
        full_path = ntpath.join(path, entry.get_longname())

        try:
            file_id = self.smbClient.getSMBServer().create(
                self.smb_tree_id,
                full_path,
                READ_CONTROL | FILE_READ_ATTRIBUTES,
                0,
                (
                    FILE_DIRECTORY_FILE
                    if entry.is_directory()
                    else FILE_NON_DIRECTORY_FILE
                ),
                FILE_OPEN,
                0,
            )
        except Exception as err:
            if entry.is_directory():
                self.logger.debug(
                    f"Could not get attributes for directory '{full_path}': {str(err)}"
                )
            else:
                self.logger.debug(
                    f"Could not get attributes for file '{full_path}': {str(err)}"
                )
            return None

        try:
            rawNtSecurityDescriptor = self.smbClient.getSMBServer().queryInfo(
                self.smb_tree_id,
                file_id,
                infoType=SMB2_0_INFO_SECURITY,
                fileInfoClass=SMB2_SEC_INFO_00,
                additionalInformation=OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | GROUP_SECURITY_INFORMATION,
                flags=0,
            )
        except Exception as err:
            if entry.is_directory():
                self.logger.debug(
                    f"Could not get attributes for directory '{full_path}': {str(err)}"
                )
            else:
                self.logger.debug(
                    f"Could not get attributes for file '{full_path}': {str(err)}"
                )
            return None

        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd.fromString(rawNtSecurityDescriptor)

        return sd

    def getRemoteName(self) -> str:
        """
        Get the remote name of the SMB server.

        Returns:
            str: The remote name of the SMB server.
        """
        return self.smbClient.getRemoteName()

    def getRemoteHost(self) -> str:
        """
        Get the remote host of the SMB server.

        Returns:
            str: The remote host of the SMB server.
        """
        return self.smbClient.getRemoteHost()

    def list_contents(self, path: Optional[str] = None) -> dict[str, SharedFile]:
        """
        Lists the contents of a specified directory on the SMB share.

        This method retrieves the contents of a directory specified by `shareName` and `path`. If `shareName` or `path`
        is not provided, it defaults to the instance's current SMB share or path. The method returns a dictionary with
        the long names of the files and directories as keys and their respective SMB entry objects as values.

        Args:
            shareName (str, optional): The name of the SMB share. Defaults to the current SMB share if None.
            path (str, optional): The directory path to list contents from. Defaults to the current path if None.

        Returns:
            dict: A dictionary with file and directory names as keys and their SMB entry objects as values.
        """

        dest_path = [
            self.smb_cwd.rstrip(ntpath.sep),
        ]
        if path is not None and len(path) > 0:
            dest_path.append(path.rstrip(ntpath.sep))
        dest_path.append("*")
        path = ntpath.normpath(ntpath.sep.join(dest_path))

        contents = {}
        entries = self.smbClient.listPath(shareName=self.smb_share, path=path)
        for entry in entries:
            contents[entry.get_longname()] = entry

        return contents

    def print_security_descriptor_table(
        self,
        security_descriptor: str,
        subject: str,
        prefix: str = " " * 13,
        table_colors: bool = False,
    ):
        """
        Print the security descriptor table.

        Args:
            security_descriptor (str): The security descriptor to print.
            subject (str): The subject of the security descriptor.
            prefix (str): The prefix to print before the security descriptor.
            table_colors (bool): Whether to use colors in the security descriptor table.

        Returns:
            str: The security descriptor table.
        """
        self.logger.print(
            self.security_descriptor_table(
                security_descriptor, subject, prefix, table_colors
            )
        )

    def security_descriptor_table(
        self,
        security_descriptor: str,
        subject: str,
        prefix: str = " " * 13,
        table_colors: bool = False,
    ) -> str:
        """ """
        if security_descriptor is not None and len(security_descriptor) == 0:
            return ""
        out_sd = ""
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd.fromString(security_descriptor)
        try:
            self.sid_resolver.resolve_sids(
                set(
                    (
                        [sd["OwnerSid"].formatCanonical()]
                        if len(sd["OwnerSid"]) != 0
                        else []
                    )
                    + (
                        [sd["GroupSid"].formatCanonical()]
                        if len(sd["GroupSid"]) != 0
                        else []
                    )
                    + [
                        acl["Ace"]["Sid"].formatCanonical()
                        for acl in sd["Dacl"]["Data"]
                        if len(acl["Ace"]["Sid"]) != 0
                    ]
                )
            )
        except Exception as err:
            self.logger.debug(f"Could not resolve SID for {subject}: {str(err)}")
            traceback.print_exc()
        max_resolved_sid_length = max(
            [len(i) for i in self.sid_resolver.cache.values()] + [0]
        )

        if len(sd["OwnerSid"]) != 0:
            resolved_owner_sid = self.sid_resolver.get_sid(
                sd["OwnerSid"].formatCanonical()
            )
            resolved_group_sid = self.sid_resolver.get_sid(
                sd["GroupSid"].formatCanonical()
            )

            if self.config.no_colors:
                out_sd += f"{prefix}Owner:   {resolved_owner_sid}\n"
                out_sd += f"{prefix}Group:   {resolved_group_sid}"
            else:
                if table_colors:
                    out_sd += f"{prefix}Owner:   [bold yellow]{resolved_owner_sid}[/bold yellow]\n"
                    out_sd += f"{prefix}Group:   [bold yellow]{resolved_group_sid}[/bold yellow]"
                else:
                    out_sd += f"{prefix}Owner:   \x1b[1m{resolved_owner_sid}\x1b[0m\n"
                    out_sd += f"{prefix}Group:   \x1b[1m{resolved_group_sid}\x1b[0m"

        for i, acl in enumerate(sd["Dacl"]["Data"]):
            resolved_sid = (
                acl["Ace"]["Sid"].formatCanonical()
                if len(acl["Ace"]["Sid"]) != 0
                else ""
            )
            if resolved_sid in ["S-1-5-32-544", "S-1-5-18"]:
                continue

            flags = []
            for flag in [
                "GENERIC_READ",
                "GENERIC_WRITE",
                "GENERIC_EXECUTE",
                "GENERIC_ALL",
                "MAXIMUM_ALLOWED",
                "ACCESS_SYSTEM_SECURITY",
                "WRITE_OWNER",
                "WRITE_DACL",
                "DELETE",
                "READ_CONTROL",
                "SYNCHRONIZE",
            ]:
                if len(acl["Ace"]["Mask"]) != 0 and acl["Ace"]["Mask"].hasPriv(
                    getattr(ldaptypes.ACCESS_MASK, flag)
                ):
                    flags.append(flag)
            if len(flags) == 0:
                continue
            try:
                resolved_sid = (
                    self.sid_resolver.get_sid(resolved_sid) if resolved_sid else ""
                )
            except Exception as err:
                self.logger.debug(
                    f"Could not resolve SID {resolved_sid} for {subject}: {str(err)}"
                )

            acl_string = prefix
            inbetween = ""
            if len(resolved_sid) < max_resolved_sid_length + 1:
                inbetween = " " * (max_resolved_sid_length + 1 - len(resolved_sid))

            if self.config.no_colors:
                acl_string += f"{resolved_sid}" + " | ".join(flags)
            else:
                acl_string += (
                    "Allowed: "
                    if acl["TypeName"] == "ACCESS_ALLOWED_ACE"
                    else "Denied:  "
                )
                if table_colors:
                    acl_string += f"[bold yellow]{resolved_sid}[/bold yellow]"
                else:
                    acl_string += f"\x1b[1m{resolved_sid}\x1b[0m"
                acl_string += inbetween
                acl_string += " | ".join(flags)
            out_sd += "\n" + acl_string
        return out_sd.lstrip("\n")

    def list_shares_detailed(self) -> dict:
        """
        get a list of available shares at the connected target

        :return: a list containing dict entries for each share
        :raise SessionError: if error
        """
        # Get the shares through RPC
        resp = srvs.hNetrShareEnum(
            dce=self.dce_srvsvc,
            level=502,
            serverName="\\\\" + self.smbClient.getRemoteHost(),
        )
        return resp["InfoStruct"]["ShareInfo"]["Level502"]["Buffer"]

    def get_share_security_descriptor(
        self,
        share_name: str,
    ) -> Optional[bytes]:
        """
        Get the share-level security descriptor for the given share_name.

        1) Try NetrShareGetInfo level 502.
        2) If that returns empty, query the remote registry:
        - HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Shares\\Security\\<share_name>
        - HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\DefaultSecurity\\SrvsvcDefaultShareInfo

        Args:
            share_name (str): The name of the share to get the security descriptor for.

        Returns:
            Optional[bytes]: The share-level security descriptor (raw bytes) for the given share_name.
        """

        # Normalize the share name.
        if not share_name.endswith("\x00"):
            query_name = share_name + "\x00"
        else:
            query_name = share_name

        # Attempt to get the security descriptor for the share through NetrShareGetInfo level 502.
        try:
            resp = srvs.hNetrShareGetInfo(
                dce=self.dce_srvsvc, netName=query_name, level=502
            )
            sd_bytes = resp["InfoStruct"]["ShareInfo502"]["shi502_security_descriptor"]
            sd = b"".join(sd_bytes) if sd_bytes else b""
            if sd:
                return sd
        except DCERPCException as e:
            # Raise for unexpected errors.
            self.logger.debug(f"NetrShareGetInfo failed: {e}")

        # Get a DCE/RPC bound connection to the WinReg endpoint.
        dce = None
        try:
            rpctransport = transport.SMBTransport(
                self.smbClient.getRemoteHost(),
                filename=r"\winreg",
                smb_connection=self.smbClient,
            )
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(rrp.MSRPC_UUID_RRP)

            # Open HKLM.
            ans = rrp.hOpenLocalMachine(dce)
            hKey = ans["phKey"]

            # Helper to query a value under a given subkey path.
            def _query_binary_value(
                subkey_path: str, value_name: str
            ) -> Optional[bytes]:
                try:
                    # Open the subkey.
                    try:
                        ans2 = rrp.hBaseRegOpenKey(dce, hKey, subkey_path + "\x00")
                        hk = ans2["phkResult"]
                    except Exception as e:
                        self.logger.debug(
                            "Registry query failed for %s\\%s: %s"
                            % (subkey_path, value_name, e)
                        )
                        if self.logger.config.debug:
                            traceback.print_exc()
                        return None

                    # Query the value.
                    try:
                        dataType, data = rrp.hBaseRegQueryValue(
                            dce, hk, value_name + "\x00"
                        )
                    except Exception as e:
                        self.logger.debug(
                            "Registry query failed for %s\\%s: %s"
                            % (subkey_path, value_name, e)
                        )
                        if self.logger.config.debug:
                            traceback.print_exc()
                        return None

                    if data is None:
                        return None
                    if isinstance(data, (list, tuple)):
                        return b"".join(data)
                    elif isinstance(data, bytes):
                        return data
                    else:
                        # Sometimes it's returned as a buffer/bytearray-like.
                        return bytes(data)

                except Exception as e:
                    self.logger.debug(
                        "Registry query failed for %s\\%s: %s"
                        % (subkey_path, value_name, e)
                    )
                    if self.logger.config.debug:
                        traceback.print_exc()
                    return None

            # Try default SrvsvcDefaultShareInfo under DefaultSecurity\SrvsvcDefaultShareInfo.
            sd = _query_binary_value(
                r"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Shares\\Security",
                share_name.rstrip("\x00"),
            )
            if sd:
                return sd

            if share_name.upper() in ["ADMIN$", "C$", "IPC$", "PRINT$"]:
                # Try per-share security value.
                sd = _query_binary_value(
                    r"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\DefaultSecurity",
                    "SrvsvcShareAdminConnect",
                )
                if sd:
                    return sd

            # Try default SrvsvcDefaultShareInfo under DefaultSecurity\SrvsvcDefaultShareInfo.
            sd = _query_binary_value(
                r"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\DefaultSecurity",
                "SrvsvcDefaultShareInfo",
            )
            if sd:
                return sd

        finally:
            try:
                if dce is not None:
                    dce.disconnect()
            except Exception:
                pass

        # Not found via registry.
        return None

    def get_share_root_security_descriptor(
        self,
        share_name: str,
    ) -> Optional[bytes]:
        """
        Get the NTFS security descriptor of the share's root folder.
        
        This is a fallback method when the share-level security descriptor cannot be
        obtained (e.g., due to insufficient privileges or remote registry being disabled).
        
        While this returns NTFS permissions rather than share-level permissions, the root
        folder's permissions are often the most relevant for understanding access control.
        
        Args:
            share_name (str): The name of the share to get the root security descriptor for.
            
        Returns:
            Optional[bytes]: The raw security descriptor bytes, or None if retrieval fails.
        """
        try:
            # We need to connect to the share if not already connected
            original_share = getattr(self, 'current_share', None)
            original_tree_id = self.smb_tree_id
            
            # Connect to the target share
            try:
                tree_id = self.smbClient.connectTree(share_name)
                self.smb_tree_id = tree_id
            except Exception as e:
                self.logger.debug(f"Could not connect to share '{share_name}' for root SD: {e}")
                return None
                
            try:
                # Open the root directory of the share
                file_id = self.smbClient.getSMBServer().create(
                    self.smb_tree_id,
                    "",  # Empty path = root of the share
                    READ_CONTROL | FILE_READ_ATTRIBUTES,
                    0,
                    FILE_DIRECTORY_FILE,
                    FILE_OPEN,
                    0,
                )
                
                try:
                    # Query the security descriptor
                    rawNtSecurityDescriptor = self.smbClient.getSMBServer().queryInfo(
                        self.smb_tree_id,
                        file_id,
                        infoType=SMB2_0_INFO_SECURITY,
                        fileInfoClass=SMB2_SEC_INFO_00,
                        additionalInformation=OWNER_SECURITY_INFORMATION
                        | DACL_SECURITY_INFORMATION
                        | GROUP_SECURITY_INFORMATION,
                        flags=0,
                    )
                    
                    return rawNtSecurityDescriptor
                    
                finally:
                    # Close the file handle
                    try:
                        self.smbClient.getSMBServer().close(self.smb_tree_id, file_id)
                    except Exception:
                        pass
                        
            finally:
                # Disconnect from the share and restore original state
                try:
                    self.smbClient.disconnectTree(tree_id)
                except Exception:
                    pass
                self.smb_tree_id = original_tree_id
                    
        except Exception as e:
            self.logger.debug(f"Could not get root folder security descriptor for share '{share_name}': {e}")
            return None

    def list_shares(self) -> dict[str, dict]:
        """
        Lists all the shares available on the connected SMB server.

        This method queries the SMB server to retrieve a list of all available shares. It populates the `shares` dictionary
        with key-value pairs where the key is the share name and the value is a dictionary containing details about the share
        such as its name, type, raw type, and any comments associated with the share.

        Returns:
            dict: A dictionary containing information about each share available on the server.
        """

        self.available_shares = {}

        if self.connected:
            if self.smbClient is not None:
                try:
                    resp = self.list_shares_detailed()
                    for share in resp:
                        # SHARE_INFO_502 structure (lmshare.h)
                        # https://learn.microsoft.com/en-us/windows/win32/api/lmshare/ns-lmshare-share_info_502
                        sharename = share["shi502_netname"][:-1]
                        sharecomment = share["shi502_remark"][:-1]
                        sharetype = share["shi502_type"]
                        sharesd = share["shi502_security_descriptor"]

                        self.available_shares[sharename.lower()] = {
                            "name": sharename,
                            "type": STYPE_MASK(sharetype),
                            "rawtype": sharetype,
                            "comment": sharecomment,
                            "security_descriptor": sharesd,
                        }
                except Exception as err:
                    self.logger.debug(f"Could not get detailed share info: {str(err)}")
                    resp = self.smbClient.listShares()

                    for share in resp:
                        # SHARE_INFO_1 structure (lmshare.h)
                        # https://learn.microsoft.com/en-us/windows/win32/api/lmshare/ns-lmshare-share_info_1
                        sharename = share["shi1_netname"][:-1]
                        sharecomment = share["shi1_remark"][:-1]
                        sharetype = share["shi1_type"]

                        self.available_shares[sharename.lower()] = {
                            "name": sharename,
                            "type": STYPE_MASK(sharetype),
                            "rawtype": sharetype,
                            "comment": sharecomment,
                        }

            else:
                self.logger.debug("Error: SMBSession.smbClient is None.")

        return self.available_shares

    # Setter / Getter

    def set_share(self, shareName: str):
        """
        Sets the current SMB share to the specified share name.

        This method updates the SMB session to use the specified share name. It checks if the share name is valid
        and updates the smb_share attribute of the SMBSession instance.

        Parameters:
            shareName (str): The name of the share to set as the current SMB share.

        Raises:
            ValueError: If the shareName is None or an empty string.
        """

        if shareName is not None:
            self.list_shares()
            if shareName.lower() in self.available_shares.keys():
                # Doing this in order to keep the case of the share adevertised by the remote machine
                self.smb_share = self.available_shares[shareName.lower()]["name"]
                self.smb_cwd = ""
                # Connects the tree
                try:
                    self.smb_tree_id = self.smbClient.connectTree(self.smb_share)
                except SessionError as err:
                    self.smb_share = None
                    self.smb_cwd = ""
                    raise Exception(
                        "Could not access share '%s': %s" % (shareName, err)
                    )
            else:
                raise Exception(
                    "Could not set share '%s', it does not exist remotely." % shareName
                )
        else:
            self.smb_share = None

    def set_cwd(self, path: Optional[str] = None):
        """
        Sets the current working directory on the SMB share to the specified path.

        This method updates the current working directory (cwd) of the SMB session to the given path if it is a valid directory.
        If the specified path is not a directory, the cwd remains unchanged.

        Parameters:
            path (str): The path to set as the current working directory.

        Raises:
            ValueError: If the specified path is not a directory.
        """

        if path is not None:
            # Set path separators to ntpath sep
            if "/" in path:
                path = path.replace("/", ntpath.sep)

            if path.startswith(ntpath.sep):
                # Absolute path
                path = path + ntpath.sep
            else:
                # Relative path to the CWD
                if len(self.smb_cwd) == 0:
                    path = path + ntpath.sep
                else:
                    path = self.smb_cwd + ntpath.sep + path

            # Path normalization
            path = ntpath.normpath(path)
            path = re.sub(r"\\+", r"\\", path)

            if path in ["", ".", ".."]:
                self.smb_cwd = ""
            else:
                if self.path_isdir(pathFromRoot=path.strip(ntpath.sep)):
                    # Path exists on the remote
                    self.smb_cwd = ntpath.normpath(path)
                else:
                    # Path does not exists or is not a directory on the remote
                    self.logger.debug("Remote directory '%s' does not exist." % path)
