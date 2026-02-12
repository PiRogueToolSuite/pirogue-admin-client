import os
import logging

log_level = os.getenv('LOG_LEVEL', 'WARNING')
logging_level = getattr(logging, log_level.upper(), None)
if not isinstance(logging_level, int):
    raise ValueError(f'Invalid log level: {log_level}')
logging.basicConfig(level=logging_level)

import argparse
import sys
from enum import Enum
from pathlib import Path

import yaml

from dataclasses import dataclass
from typing import TextIO

from grpc import RpcError
from pirogue_admin_client import PirogueAdminClientAdapter


@dataclass
class ClientCallContext:
    host: str
    port: int
    token: str
    certificate: str = None
    func = None
    commit: bool = False
    from_scratch: bool = False


def _adapter(ctx: ClientCallContext):
    return PirogueAdminClientAdapter(ctx.host, ctx.port, ctx.token, ctx.certificate)


def call_function(ctx: ClientCallContext, function, kwargs, out_fs: TextIO = None):

    err_msg = 0

    if out_fs is None:
        out_fs = sys.stdout

    paca = _adapter(ctx)
    if not hasattr(paca, function):
        raise ValueError(f'"{function}" is not a valid function')
    func = getattr(paca, function)

    try:
        result = func(**kwargs)

        if type(result) in [dict, list]:
            yaml.safe_dump(result, out_fs)
        elif type(result) is Enum:
            out_fs.write(f'{result.name}\n')
        elif result is None:
            print(f'{function} done.')
        elif type(result) is str:
            out_fs.write(f'{result}\n')
        else:
            print('answer is an unsupported type:', type(result))
            out_fs.write(f'{result}\n')
    except RpcError as rpc_error:
        err_msg = f'error: {rpc_error.details()}'

    if out_fs is not sys.stdout:
        out_fs.close()

    return err_msg

def main():
    parser = argparse.ArgumentParser(
        description='PiRogue administration client',
    )
    parser.add_argument('--token',
                        help='use TOKEN for authentication against PiRogueAdmin server')

    parser.add_argument('--host',
                        default=None,
                        help='set PiRogueAdmin target server to be HOST')

    parser.add_argument('--port',
                        type=int, default=None,
                        help='set PiRogueAdmin target port to be PORT')

    parser.add_argument('--certificate', default=argparse.SUPPRESS,
                        help="certificate file to use if not public, use explicit 'public' value"
                             " if you want to force check against publicly known certificate"
                             " (like letsencrypt certificate)")

    parser.add_argument('--save-configuration', '--save',
                        action='store_true',
                        help='save configuration for future client usage')


    section_subparser = parser.add_subparsers(title="Administration sections", description="main description")

    #
    # All intermediate parsers
    system_parser = section_subparser.add_parser('system', help='System related administration')
    external_parser = section_subparser.add_parser('external-network', help='External network related administration')
    isolated_parser = section_subparser.add_parser('isolated-network', help='Isolated network related administration')
    vpn_parser = section_subparser.add_parser('vpn', help='VPN related administration')
    wifi_parser = section_subparser.add_parser('wifi', help='WiFi related administration')
    suricata_rules_parser = section_subparser.add_parser('suricata-rules', help='Suricata related administration')
    dashboard_parser = section_subparser.add_parser('dashboard', help='Dashboard related administration')
    access_parser = section_subparser.add_parser('access', help='Access related administration')

    #
    # System related subparser
    system_subparser = system_parser.add_subparsers(title="System administration")
    #
    system_get_configuration_tree = system_subparser.add_parser(
        'get-configuration-tree',
        help='get information about the current configuration as a dependencies tree')
    system_get_configuration_tree.set_defaults(func='get_configuration_tree')
    #
    system_get_configuration = system_subparser.add_parser(
        'get-configuration',
        help='get the current configuration')
    system_get_configuration.set_defaults(func='get_configuration')
    #
    system_get_operating_mode = system_subparser.add_parser(
        'get-operating-mode',
        help='get the current operating mode')
    system_get_operating_mode.set_defaults(func='get_operating_mode')
    #
    system_get_status = system_subparser.add_parser(
        'get-status',
        help='get system status')
    system_get_status.set_defaults(func='get_status')
    #
    system_get_packages_info = system_subparser.add_parser(
        'get-packages-info',
        help='get system packages information')
    system_get_packages_info.set_defaults(func='get_packages_info')
    #
    system_get_hostname = system_subparser.add_parser(
        'get-hostname',
        help='get system hostname')
    system_get_hostname.set_defaults(func='get_hostname')
    #
    system_set_hostname = system_subparser.add_parser(
        'set-hostname',
        help='set system hostname')
    system_set_hostname.add_argument('hostname')
    system_set_hostname.set_defaults(func='set_hostname')
    #
    system_get_locale = system_subparser.add_parser(
        'get-locale',
        help='set system hostname')
    system_get_locale.set_defaults(func='get_locale')
    #
    system_set_locale = system_subparser.add_parser(
        'set-locale',
        help='set system hostname')
    system_set_locale.add_argument('locale')
    system_set_locale.set_defaults(func='set_locale')
    #
    system_get_timezone = system_subparser.add_parser(
        'get-timezone',
        help='set system hostname')
    system_get_timezone.set_defaults(func='get_timezone')
    #
    system_set_timezone = system_subparser.add_parser(
        'set-timezone',
        help='set system hostname')
    system_set_timezone.add_argument('timezone')
    system_set_timezone.set_defaults(func='set_timezone')
    #
    system_list_connected_devices = system_subparser.add_parser(
        'list-connected-devices',
        help='list all connected devices to the PiRogue system')
    system_list_connected_devices.set_defaults(func='list_connected_devices')

    #
    # External related subparser
    external_subparser = external_parser.add_subparsers(title="External network administration")
    #
    external_enable_public_access = external_subparser.add_parser(
        'enable-public-access',
        help='enable administration public access on EXTERNAL interface')
    external_enable_public_access.add_argument('--domain', required=True)
    external_enable_public_access.add_argument('--email', required=True)
    external_enable_public_access.set_defaults(func='enable_external_public_access')
    #
    external_disable_public_access = external_subparser.add_parser(
        'disable-public-access',
        help='close administration public access from EXTERNAL interface')
    external_disable_public_access.set_defaults(func='disable_external_public_access')

    #
    # Isolated related subparser
    isolated_subparser = isolated_parser.add_subparsers(title="Isolated network administration")
    #
    isolated_open_port = isolated_subparser.add_parser(
        'open-port',
        help='open one port on EXTERNAL interface')
    isolated_open_port.add_argument('incoming_port', type=int)
    isolated_open_port.add_argument('--outgoing-port', type=int, default=None)
    isolated_open_port.set_defaults(func='open_isolated_port')
    #
    isolated_close_port = isolated_subparser.add_parser(
        'close-port',
        help='close all opened ports on EXTERNAL interface. close only one specific port if given')
    isolated_close_port.add_argument('--incoming-port', type=int, default=None)
    isolated_close_port.set_defaults(func='close_isolated_port')
    #
    isolated_list_open_ports = isolated_subparser.add_parser(
        'list-open-ports',
        help='list open ports on EXTERNAL interface')
    isolated_list_open_ports.set_defaults(func='list_isolated_open_ports')

    #
    # VPN related subparser
    vpn_subparser = vpn_parser.add_subparsers(title="VPN administration")
    #
    vpn_list_peers = vpn_subparser.add_parser(
        'list-peers',
        help='list all registered VPN peers')
    vpn_list_peers.set_defaults(func='list_vpn_peers')
    #
    vpn_get_peer = vpn_subparser.add_parser(
        'get-peer',
        help='retrieve peer details')
    vpn_get_peer.add_argument('idx')
    vpn_get_peer.set_defaults(func='get_vpn_peer')
    #
    vpn_get_peer_config = vpn_subparser.add_parser(
        'get-peer-config',
        help='retrieve peer configuration file content')
    vpn_get_peer_config.add_argument('idx')
    vpn_get_peer_config.set_defaults(func='get_vpn_peer_config')
    #
    vpn_add_peer = vpn_subparser.add_parser(
        'add-peer',
        help='retrieve peer details')
    vpn_add_peer.add_argument('--comment')
    vpn_add_peer.add_argument('--public-key')
    vpn_add_peer.set_defaults(func='add_vpn_peer')
    #
    vpn_delete_peer = vpn_subparser.add_parser(
        'delete-peer',
        help='revoke access and delete a specific peer')
    vpn_delete_peer.add_argument('idx')
    vpn_delete_peer.set_defaults(func='delete_vpn_peer')

    #
    # VPN related subparser
    wifi_subparser = wifi_parser.add_subparsers(title="WiFi administration")
    #
    wifi_get_configuration = wifi_subparser.add_parser(
        'get-configuration',
        help='get the current wifi configuration')
    wifi_get_configuration.set_defaults(func='get_wifi_configuration')
    #
    wifi_set_configuration = wifi_subparser.add_parser(
        'set-configuration',
        help='set a new wifi configuration',
        description='set a new wifi configuration specifying one or more argument',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''\
examples:
  - only change wifi passphrase to 'foo':
    pirogue-admin-client wifi set-configuration --passphrase 'foo'
  - change wifi passphrase and ssid:
    pirogue-admin-client wifi set-configuration --ssid 'Foo_Network' --passphrase 'bar'
               ''')
    wifi_set_configuration.add_argument('--ssid', type=str, default=None)
    wifi_set_configuration.add_argument('--passphrase', type=str, default=None)
    wifi_set_configuration.add_argument('--country-code', type=str, default=None)
    wifi_set_configuration.set_defaults(func='set_wifi_configuration')

    """
    # FIXME: Suricate rules management disabled for now
    #
    # Suricata rules related subparser
    suricata_rules_subparser = suricata_rules_parser.add_subparsers(title="Suricata administration")
    #
    sr_list_suricata_rules_sources = suricata_rules_subparser.add_parser(
        'list-sources',
        help='list all active suricata rules sources')
    sr_list_suricata_rules_sources.set_defaults(func='list_suricata_rules_sources')
    #
    sr_delete_suricata_rules_source = suricata_rules_subparser.add_parser(
        'del-source',
        help='delete one suricata rules source')
    sr_delete_suricata_rules_source.add_argument('url')
    sr_delete_suricata_rules_source.set_defaults(func='delete_suricata_rules_source')
    #
    sr_add_suricata_rules_source = suricata_rules_subparser.add_parser(
        'add-source',
        help='add one suricata rules source')
    sr_add_suricata_rules_source.add_argument('name')
    sr_add_suricata_rules_source.add_argument('url')
    sr_add_suricata_rules_source.set_defaults(func='add_suricata_rules_source')
    """

    #
    # Dashboard related subparser
    dashboard_subparser = dashboard_parser.add_subparsers(title="Dashboard administration")
    #
    dashboard_set_configuration = dashboard_subparser.add_parser(
        'set-configuration',
        help='set dashboard configuration')
    dashboard_set_configuration.add_argument('--password')
    dashboard_set_configuration.set_defaults(func='set_dashboard_configuration')
    #
    dashboard_get_configuration = dashboard_subparser.add_parser(
        'get-configuration',
        help='get dashboard configuration')
    dashboard_get_configuration.set_defaults(func='get_dashboard_configuration')

    #
    # Access related subparser
    access_subparser = access_parser.add_subparsers(title="Access administration")
    #
    access_reset_administration_token = access_subparser.add_parser(
        'reset-administration-token',
        help='renew the administration token.'
             'Revoke the current token then generate a new one.')
    access_reset_administration_token.set_defaults(func='reset_administration_token')
    #
    access_get_administration_token = access_subparser.add_parser(
        'get-administration-token',
        help='get the current working administration token (needed to connect remotely)')
    access_get_administration_token.set_defaults(func='get_administration_token')
    #
    access_get_administration_certificate = access_subparser.add_parser(
        'get-administration-certificate',
        help='get the current self-signed certificate (needed to connect remotely)')
    access_get_administration_certificate.set_defaults(func='get_administration_certificate')
    #
    access_get_administration_clis = access_subparser.add_parser(
        'get-administration-clis',
        help='get a set of shell commands to configuration a new remote pirogue-admin-client')
    access_get_administration_clis.set_defaults(func='get_administration_clis')
    #
    access_create_user_access = access_subparser.add_parser(
        'create-user-access',
        help='create a new user access entry (with no permissions by default)')
    access_create_user_access.set_defaults(func='create_user_access')
    #
    access_get_user_access = access_subparser.add_parser(
        'get-user-access',
        help='retrieve user access details given its index')
    access_get_user_access.add_argument('idx')
    access_get_user_access.set_defaults(func='get_user_access')
    #
    access_list_user_accesses = access_subparser.add_parser(
        'list-user-accesses',
        help='list all active user accesses')
    access_list_user_accesses.set_defaults(func='list_user_accesses')
    #
    access_delete_user_access = access_subparser.add_parser(
        'delete-user-access',
        help='delete a user access given its index')
    access_delete_user_access.add_argument('idx')
    access_delete_user_access.set_defaults(func='delete_user_access')
    #
    access_reset_user_access_token = access_subparser.add_parser(
        'reset-user-access-token',
        help='reset the token of a given user access index')
    access_reset_user_access_token.add_argument('idx')
    access_reset_user_access_token.set_defaults(func='reset_user_access_token')
    #
    access_get_permission_list = access_subparser.add_parser(
        'get-permission-list',
        help='get all available permissions for each accessible services')
    access_get_permission_list.set_defaults(func='get_permission_list')
    #
    access_set_user_access_permissions = access_subparser.add_parser(
        'set-user-access-permissions',
        help='change permissions of a given user access index',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''\
idx:
  the user access index to modify
  
permissions:
  syntax: [MODIFIER]SERVICE[:PERMISSION]
  multiple changes are expressed as a space-separated list of permissions

MODIFIER:
  + adds the given SERVICE:PERMISSION
  - removes the given SERVICE:PERMISSION
  <none> sets the given SERVICE:PERMISSION (and remove all other permissions)

SERVICE:
  a service name as expressed by `get-permission-list`

PERMISSION:
  a permission name for a given SERVICE as expressed by `get-permission-list`

Before configuring permissions on user accesses, get the list of all available permissions with the
`get-permission-list` command:
  pirogue-admin-client access get-permission-list

Permissions are organized as a tree with service name as keys and permission name as leafs:
  - Service1:
    - Permission1
    - Permission2
  - Service2:
    - Permission3
    - Permission4 

Examples:
  (assuming all this example modifies the user access of idx 8)
  - adds all permissions of the 'System' service:
    pirogue-admin-client access set-user-access-permissions -- 8 +System  
  - removes one permission:
    pirogue-admin-client access set-user-access-permissions -- 8 -System:GetConfiguration
  - do both of previous command at once:
    pirogue-admin-client access set-user-access-permissions -- 8 +System -System:GetConfiguration
  - removes all permissions and only sets the given ones:
    pirogue-admin-client access set-user-access-permissions -- 8 System:GetStatus
        ''')
    access_set_user_access_permissions.add_argument('idx')
    access_set_user_access_permissions.add_argument('permissions', nargs='+')
    access_set_user_access_permissions.set_defaults(func='set_user_access_permissions')

    args = parser.parse_args()

    certification_str = None
    if 'certificate' in args:
        if args.certificate == 'public':
            certification_str = 'public'
        else:
            certification_str = Path(args.certificate).read_text()

    client_ctx_call = ClientCallContext(args.host, args.port, args.token, certification_str)

    err_msg = 0

    if 'func' in args:
        kwargs = dict(vars(args))
        kwargs.pop('host')
        kwargs.pop('port')
        kwargs.pop('token')
        kwargs.pop('save_configuration')
        kwargs.pop('certificate', False)
        func = kwargs.pop('func')
        err_msg = call_function(client_ctx_call, func, kwargs)

    if args.save_configuration:
        _adapter(client_ctx_call).save_configuration()
        print('configuration saved.')

    return err_msg

if __name__ == '__main__':
    sys.exit(main())
