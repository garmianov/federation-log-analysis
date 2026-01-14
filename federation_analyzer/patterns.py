"""
Regex patterns and error classification dictionaries for federation log parsing.
"""

import re

# =============================================================================
# PATTERNS FOR FEDERATION LOG PARSING
# =============================================================================

# Timestamp pattern: 2026-01-04T21:06:38.339-08:00
TIMESTAMP_PATTERN = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})')

# Store pattern: Store 51389 (vNVR) or Store_51389
STORE_PATTERN = re.compile(r'Store[\s_](\d{4,5})(?:\s*\([^)]*\))?')

# IP and Port pattern
IP_PORT_PATTERN = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)')

# Federation group pattern
FED_GROUP_PATTERN = re.compile(r'(SBUXSCRoleGroup\d+)')

# Error classification patterns
ERROR_PATTERNS = {
    'tls_handshake_error': [
        'TlsConnectionException',
        'error completing the handshake',
        'SSL handshake',
        'TLS handshake'
    ],
    'connection_timeout': [
        'did not properly respond after a period of time',
        'connection attempt failed',
        'timed out',
        'timeout'
    ],
    'connection_refused': [
        'connection was forcibly closed',
        'actively refused',
        'Connection refused',
        'target machine actively refused'
    ],
    'host_unreachable': [
        'host has failed to respond',
        'No route to host',
        'network is unreachable',
        'host is down'
    ],
    'socket_exception': [
        'SocketException',
        'socket error',
        'WSAECONNRESET'
    ],
    'proxy_disconnect': [
        'logged off',
        'federated proxy',
        'Initial sync context is null',
        'proxy connection lost'
    ],
    'sql_connection': [
        'SqlException',
        'SQL Server',
        'database connection'
    ],
    'certificate_error': [
        'certificate',
        'cert validation',
        'trust relationship'
    ],
    'scheduling_reconnect': [
        'Scheduling reconnection',
        'reconnect attempt',
        'startDelay'
    ],
    # Internal Error patterns - application-layer failures
    'internal_error_logon': [
        'result Failure () while at step Waiting for message',
        'LogonFailedEventArgs.FailureCode=Failure',
        'OnFederatedProxy_LogonFailed'
    ],
    'internal_error_prefetch': [
        'prefetch failed',
        'Prefetch query failed',
        'The prefetch failed (Base)',
        'The prefetch failed (DirectoryRole)',
        'The prefetch failed (DirectoryServers)'
    ],
    'internal_error_directory': [
        'not currently connected to the Directory',
        'Directory and cannot handle your request'
    ],
    'internal_error_sync': [
        'Entity synchronization failed',
        'Aborting synchronization',
        'Failed to map local and remote custom fields'
    ],
    'internal_error_tls_auth': [
        'TLS authentication failed',
        'TLS authentication failed when connecting'
    ]
}

# Internal Error sub-type patterns for detailed classification
INTERNAL_ERROR_SUBTYPES = {
    'empty_redirection': re.compile(r'result Failure \(\) while at step Waiting for message: RedirectionResponseMessage'),
    'empty_logon': re.compile(r'result Failure \(\) while at step Waiting for message: LogOnResultMessage'),
    'prefetch_base': re.compile(r'prefetch failed \(Base\)', re.I),
    'prefetch_directory_role': re.compile(r'prefetch failed \(DirectoryRole\)', re.I),
    'prefetch_directory_servers': re.compile(r'prefetch failed \(DirectoryServers\)', re.I),
    'directory_disconnected': re.compile(r'not currently connected to the Directory'),
    'tls_auth_failed': re.compile(r'TLS authentication failed'),
    'handshake_error': re.compile(r'error completing the handshake'),
    'read_timeout': re.compile(r'Read timeout occured'),
    'transport_read_error': re.compile(r'Unable to read data from the transport connection'),
    'sync_aborted': re.compile(r'Aborting synchronization'),
    'entity_sync_failed': re.compile(r'Entity synchronization failed'),
    'custom_fields_failed': re.compile(r'Failed to map local and remote custom fields'),
    'logon_failed_event': re.compile(r'OnFederatedProxy_LogonFailed.*FailureCode=Failure'),
    'security_token_error': re.compile(r'Raising WFSecurityTokensManager')
}

# Severity indicators
SEVERITY_PATTERNS = {
    'fatal': re.compile(r'\(Fatal\)', re.I),
    'error': re.compile(r'\(Error\)', re.I),
    'warning': re.compile(r'\(Warning\)', re.I),
    'exception': re.compile(r'Exception', re.I)
}
