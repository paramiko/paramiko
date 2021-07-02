#!/usr/bin/env python
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
Sample script to show how to use paramiko's SOCKS proxy server functionality.

This script connects to a configured SSH server and opens a local
SOCKS5 proxy which tunnels all traffic over the SSH connection (similar to
`openssh -D`). It then configures a requests session to use this SOCKS5 proxy
to fetch the configured URL tunneled through the SSH connection.

Please note that you need to install requests with socks proxy support
(`requests[socks]`) for this demo to work.
"""

import getpass

from optparse import OptionParser

import requests

from paramiko.client import AutoAddPolicy, SSHClient


DEFAULT_SSH_PORT = 22
DEFAULT_SOCKS_ADDR = "localhost:1080"
DEFAULT_SOCKS_PORT = 1080


def get_host_port(spec, default_port):
    """
    parse 'hostname:22' into a host and port, with the port optional
    """
    args = (spec.split(":", 1) + [default_port])[:2]
    args[1] = int(args[1])
    return args[0], args[1]


def parse_options():
    parser = OptionParser(
        usage="usage: %prog [options] url-to-fetch",
        description="Demo for providing a SOCKS proxy and using it "
                    "with requests to request an URL",
    )
    parser.add_option(
        "-u",
        "--user",
        action="store",
        type="string",
        help="username for SSH authentication",
    )
    parser.add_option(
        "-K",
        "--key",
        action="store",
        type="string",
        dest="keyfile",
        default=None,
        help="private key file to use for SSH authentication",
    )
    parser.add_option(
        "",
        "--no-key",
        action="store_false",
        dest="look_for_keys",
        default=True,
        help="don't look for or use a private key file",
    )
    parser.add_option(
        "-P",
        "--password",
        action="store_true",
        dest="readpass",
        default=False,
        help="read password (for key or password auth) from stdin",
    )
    parser.add_option(
        "-r",
        "--remote",
        action="store",
        type="string",
        metavar="host:port",
        help="Host and port of the SSH server to connect to",
    )
    parser.add_option(
        "-s",
        "--socks-addr",
        action="store",
        type="string",
        default=DEFAULT_SOCKS_ADDR,
        metavar="host:port",
        help="Host and port the SOCKS proxy should bind to. Defaults to %s" %
             DEFAULT_SOCKS_ADDR,
    )
    options, args = parser.parse_args()

    if len(args) != 1:
        parser.error("Incorrect number of positional arguments.")
    if not options.user or not options.remote or not options.socks_addr:
        parser.error("Mandatory options missing.")

    ssh_server, ssh_port = get_host_port(options.remote, DEFAULT_SSH_PORT)
    socks_addr, socks_port = get_host_port(
        options.socks_addr, DEFAULT_SOCKS_PORT
    )
    return (
        ssh_server,
        ssh_port,
        options.user,
        options.keyfile,
        options.look_for_keys,
        options.readpass,
        socks_addr,
        socks_port,
        args[0]
    )


def main():
    options = parse_options()
    ssh_server = options[0]
    ssh_port = options[1]
    user = options[2]
    keyfile = options[3]
    look_for_keys = options[4]
    readpass = options[5]
    socks_addr = options[6]
    socks_port = options[7]
    url_to_fetch = options[8]

    password = None
    if readpass:
        password = getpass.getpass("Enter SSH password: ")

    with SSHClient() as ssh_client:
        ssh_client.load_system_host_keys()
        ssh_client.set_missing_host_key_policy(AutoAddPolicy())

        try:
            ssh_client.connect(
                ssh_server,
                port=ssh_port,
                username=user,
                key_filename=keyfile,
                look_for_keys=look_for_keys,
                password=password,
            )
        except Exception as e:
            print("*** Failed to connect to server: {}".format(e))
            exit(1)

        proxy = ssh_client.open_socks_proxy(
            bind_address=socks_addr,
            port=socks_port
        )

        # Example of how to use with requests.
        # Using the socks5h protocol for resolving host names on SOCKS
        # server side works as well.
        proxies = {
            'http': 'socks5://{}:{}'.format(socks_addr, socks_port),
            'https': 'socks5://{}:{}'.format(socks_addr, socks_port),
        }
        session = requests.Session()
        session.proxies.update(proxies)
        response = session.get(url_to_fetch)
        print(response.text)

        # Closing the SOCKS proxy is optional, as it would get closed together
        # with the SSHClient as well.
        proxy.close()


if __name__ == '__main__':
    main()
