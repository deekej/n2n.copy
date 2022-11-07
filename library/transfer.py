#!/usr/bin/python

# Copyright: (c) 2022, Dee'Kej <devel@deekej.io>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: transfer

short_description: Extracts the contents of given container image

version_added: "1.0.0"

description: This module transfers specified file(s) to/from a remote host,
             using SSH2 and SFTP. It is build on top of paramiko library,
             and its main usage is to be used as a simple way to transfer
             file(s) between 2 remote Ansible nodes.

             The transfer is being done between the nodes directly - i.e.
             no transfer to control node and remote like with the fetch-copy
             workflow, and there's no brainteaser for the direction of
             transfer like in 'synchronize' module's case...

             On top of that, this module allows to use SSH keys encrypted with
             passphrase.

options:
    remote:
        description: Hostname of the remote node to connect to.
        required: true
        aliases: hostname
        type: str

    method:
        description: Direction of transfer between the nodes.
        required: true
        choices:
            - push
            - pull
        aliases: direction
        type: str

    src:
        description:
            - Source path of the file to be transfered to destination.
            - Mutually exclusive with 'files' option.
            - Either 'src' / 'dest' or 'files' options have to be defined.
        required: false
        type: str
    dest:
        description:
            - Destination path of the file to be transfered from source.
            - Mutually exclusive with 'files' option.
            - Either 'src' / 'dest' or 'files' options have to be defined.
        required: false
        type: str

    files:
        description:
            - List of files to be transfered from source path to destination.
            - Each element of the list is a dictionary with 'src' / 'dest' keys.
            - See 'src' and 'dest' options for definition of these keys.
            - Mutually exclusive with 'src' and 'dest' options.
            - Either 'src' / 'dest' or 'files' options have to be defined.
        required: false
        type: list

    force:
        description:
            - Forces the transfer even when the size and modification time
              stats of 'src' and 'dest' are the same.
            - Default: false
        required: false
        type: bool

    port:
        description:
            - Specifies different port for connection to remote node.
            - Default: 22
        required: false
        type: int

    username:
        description:
            - Specifies different username for connection to remote node.
            - Default: ANSIBLE_NET_USERNAME (environment variable) / None
        required: false
        type: str

    password:
        description:
            - Specifies password to use when connecting to remote node.
            - Default: ANSIBLE_NET_PASSWORD (environment variable) / None
        required: false
        type: str

    ssh_keyfile:
        description:
            - Path to private SSH key to use when connection to remote node.
            - Default: ANSIBLE_NET_SSH_KEYFILE (environment variable) / None
        required: false
        type: str

    passphrase:
        description:
            - Specifies passphrase to use for decrypting of SSH key.
            - Default: None
        required: false
        type: str

    look_for_keys:
        description:
            - Allows searching for discoverable private keys in ~/.ssh/ folder.
            - Default: True
        required: false
        type: bool

    allow_ssh_agent:
        description:
            - Allows usage of ssh-agent on the initiator node.
            - Default: True
        required: false
        type: bool

    auth_timeout:
        description:
            - Optional timeout (in seconds) to wait for authentication response.
            - Default: None
        required: false
        type: int

    timeout:
        description:
            - Optional timeout (in seconds) to wait for TCP connection.
            - Default: None
        required: false
        type: int

    compress:
        description:
            - Allows enabling compression for the underlying SSH2 connection.
            - Default: False
        required: false
        type: bool

    gss_auth:
        description:
            - Allows usage of GSS-API authentication.
            - Default: False
        required: false
        type: bool

    gss_host:
        description:
            - The targets name in Kerberos database.
            - Default: remote hostname
        required: false
        type: str

    gss_kex:
        description:
            - Perform GSS-API Key Exchange and user authentication.
            - Default: False
        required: false
        type: bool

    gss_trust_dns:
        description:
            - Indicates whether or not the DNS is trusted to securely
              canonicalize the name of the remote being connected to.
            - Default: True
        required: false
        type: bool

    gss_deleg_creds:
        description:
            - Whether or not to delegate GSS-API client credentials.
            - Default: True
        required: false
        type: bool

author:
    - Dee'Kej (@deekej)
'''

EXAMPLES = r'''
- name: Upload single file from localhost to remote host
  transfer:
    remote:       hostname.example.com
    method:       push
    src:          /etc/.backup/ansible/ansible.cfg
    dest:         /etc/ansible/ansible.cfg
    force:        true

- name: Download single file from remote host to localhost
  transfer:
    remote:       hostname.example.com
    method:       pull
    src:          /etc/ansible/ansible.cfg
    dest:         /etc/.backup/ansible/ansible.cfg

- name: Transfer multiple files from one remote host to another [role]
  transfer:
    remote:       hostname.example.com
    method:       push
    files:
      - src:      /etc/.backup/ansible/ansible.cfg
        dest:     /etc/ansible/ansible.cfg
      - src:      /etc/.backup/ansible/hosts
        dest:     /etc/ansible/hosts
   delegate_to:   backup.example.com

- name: Transfer multiple files from one remote host to another [playbook]
  hosts: backup.example.com
  tasks:
    - name: Transfer system-wide Ansible configuration files
      transfer:
        remote:   hostname.example.com
        method:   push
        files:
          - src:  /etc/.backup/ansible/ansible.cfg
            dest: /etc/ansible/ansible.cfg
          - src:  /etc/.backup/ansible/hosts
            dest: /etc/ansible/hosts
'''

# ---------------------------------------------------------------------

# TODO:
#   1) Add support for 'delayed updates' - the same way 'synchronize'
#      module does it... https://docs.ansible.com/ansible/latest/collections/ansible/posix/synchronize_module.html#parameter-delay_updates
#
#   2) Add support for transfer of whole folders. This needs additional
#      support from paramiko first though...
#
#   3) Add support for changing file's owner / group / mode.

# =====================================================================

import os
import paramiko

from collections import namedtuple

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback

# ---------------------------------------------------------------------

# Returns a new files list where the 'src' / 'dest' keys are renamed to
# 'localpath' / 'remotepath' - depending on the transfer direction...
def get_updated_files_list(files, direction):
    updated_files = []

    for file in files:
        tmp_dir = {}

        if direction == 'push':
            tmp_dir['localpath']  = file['src']
            tmp_dir['remotepath'] = file['dest']
        else:
            tmp_dir['localpath']  = file['dest']
            tmp_dir['remotepath'] = file['src']

        updated_files.append(tmp_dir)

    return updated_files


# Returns the stat info for both local and remote file. In case any
# (local or remote) file does not exist, then None is return correspondingly.
def get_stats(sftp, file):
    stats = namedtuple('stats', ['local', 'remote'])

    try:
        local = os.stat(file['localpath'])
    except IOError:
        local = None

    try:
        remote = sftp.stat(file['remotepath'])
    except IOError:
        remote = None

    return stats(local, remote)


# Compares if the files are same or not. The comparison is based on the
# st_size and st_mtime information from stat() functions...
def files_differ(stats):
    if not stats.local or not stats.remote:
        return True

    # NOTE: We need to typecast the modification time of local file,
    #       because os.stat() uses floats to represent time, while the
    #       stat() from paramiko's SFTP uses integers...
    if (stats.local.st_size != stats.remote.st_size
            or int(stats.local.st_mtime) != stats.remote.st_mtime):
        return True
    else:
        return False

# Transfer the file in the requested direction...
def transfer(sftp, file, stats, direction):
    # NOTE: We also need to update access / modification times for the
    #       remote file to remain idempotent for future runs...
    #
    #       And we need to typecast the modification time of local file,
    #       because os.stat() uses floats to represent time, while the
    #       stat() from paramiko's SFTP uses integers...
    if direction == 'push':
        sftp.put(file['localpath'], file['remotepath'])
        sftp.utime(file['remotepath'], (int(stats.local.st_atime), int(stats.local.st_mtime)))
    else:
        sftp.get(file['remotepath'], file['localpath'])
        os.utime(file['localpath'], (stats.remote.st_atime, stats.remote.st_mtime))

# ---------------------------------------------------------------------

def run_module():
    # Ansible Module arguments initialization:
    module_args = dict(
        remote          = dict(type='str',   required=True, aliases=['hostname']),
        method          = dict(type='str',   required=True, choices=['push', 'pull'], aliases=['direction']),
        force           = dict(type='bool',  required=False, default=False),

        # ---| Mutually exclusive options |----------------------------
        src             = dict(type='str',   required=False, default=None),
        dest            = dict(type='str',   required=False, default=None),

        files           = dict(type='list',  required=False, default=None, elements='dict'),

        # ---| Connection options |------------------------------------
        port            = dict(type='int',   required=False, default=22),
        username        = dict(type='str',   fallback=(env_fallback,['ANSIBLE_NET_USERNAME'])),
        password        = dict(type='str',   fallback=(env_fallback,['ANSIBLE_NET_PASSWORD']),    no_log=True),
        ssh_keyfile     = dict(type='str',   fallback=(env_fallback,['ANSIBLE_NET_SSH_KEYFILE']), no_log=True, aliases=['key_filename']),
        passphrase      = dict(type='str',   required=False, default=None, no_log=True),
        look_for_keys   = dict(type='bool',  required=False, default=True),
        allow_ssh_agent = dict(type='bool',  required=False, default=True, aliases=['allow_agent']),
        auth_timeout    = dict(type='float', required=False, default=None),
        timeout         = dict(type='float', required=False, default=None),
        compress        = dict(type='bool',  required=False, default=False),

        # ---| GSSAPI / Kerberos options |-----------------------------
        gss_auth        = dict(type='bool',  required=False, default=False),
        gss_host        = dict(type='bool',  required=False, default=None),
        gss_kex         = dict(type='bool',  required=False, default=False),
        gss_trust_dns   = dict(type='bool',  required=False, default=True),
        gss_deleg_creds = dict(type='bool',  required=False, default=True)
    )

    # Parsing of Ansible Module arguments:
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        mutually_exclusive=[
            ('files', 'src'),
            ('files', 'dest'),
        ],
        required_together=[
            ('src', 'dest')
        ],
        required_one_of=[
            ('files', 'src'),
            ('files', 'dest')
        ]
    )

    # -----------------------------------------------------------------

    direction       = module.params['method']
    src             = module.params['src']
    dest            = module.params['dest']
    files           = module.params['files']
    force           = module.params['force']

    hostname        = module.params['remote']
    port            = module.params['port']
    username        = module.params['username']
    password        = module.params['password']
    ssh_keyfile     = module.params['ssh_keyfile']
    passphrase      = module.params['passphrase']
    look_for_keys   = module.params['look_for_keys']
    allow_ssh_agent = module.params['allow_ssh_agent']
    auth_timeout    = module.params['auth_timeout']
    timeout         = module.params['timeout']
    compress        = module.params['compress']

    gss_auth        = module.params['gss_auth']
    gss_host        = module.params['gss_host']
    gss_kex         = module.params['gss_kex']
    gss_trust_dns   = module.params['gss_trust_dns']
    gss_deleg_creds = module.params['gss_deleg_creds']

    if ssh_keyfile:
        ssh_keyfile  = os.path.expanduser(module.params['ssh_keyfile'])

    for file in files or []:
        file.setdefault('src', None)
        file.setdefault('dest', None)

    # -----------------------------------------------------------------

    result = dict(
        changed = False,
        method = direction,
        src = src,
        dest = dest,
        files = files,
        force = force,
        remote = hostname,
        port = port,
        username = username,
        password = password,
        ssh_keyfile = ssh_keyfile,
        passphrase = passphrase,
        look_for_keys = look_for_keys,
        allow_ssh_agent = allow_ssh_agent,
        auth_timeout = auth_timeout,
        timeout = timeout,
        compress = compress,
        gss_auth = gss_auth,
        gss_host = gss_host,
        gss_kex = gss_kex,
        gss_trust_dns = gss_trust_dns,
        gss_deleg_creds = gss_deleg_creds,
    )

    # -----------------------------------------------------------------

    # Make sure each element of files has 'src' and 'dest' defined:
    for file in files or []:
        if not file['src']:
            module.fail_json(msg="missing 'src' key in 'files' list", **result)

        if not file['dest']:
            module.fail_json(msg="missing 'dest' key in 'files' list", **result)

    # Prepare a list of files to be transferred even for a single file:
    if not files:
        files = [
            {
                'src':   src,
                'dest':  dest,
            }
        ]

    # Get updated list where the 'src' / 'dest' are renamed to
    # 'localpath' / 'remotepath' for each file - based on the direction:
    files = get_updated_files_list(files, direction)

    # Expand the home paths for the localhost files:
    for file in files:
        file['localpath'] = os.path.expanduser(file['localpath'])

    # -----------------------------------------------------------------

    # Establish the SSH2 connection to the remote host:
    try:
        connect = paramiko.SSHClient()
        connect.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connect.load_system_host_keys()

        connect.connect(
            hostname,
            port = port,
            username = username,
            password = password,
            key_filename = ssh_keyfile,
            passphrase = passphrase,
            look_for_keys = look_for_keys,
            allow_agent = allow_ssh_agent,
            auth_timeout = auth_timeout,
            timeout = timeout,
            compress = compress,
            gss_auth = gss_auth,
            gss_host = gss_host,
            gss_kex = gss_kex,
            gss_trust_dns = gss_trust_dns,
            gss_deleg_creds = gss_deleg_creds
        )
    except paramiko.AuthenticationException as ex:
        module.fail_json(msg="authentication to %s failed: %s" % (hostname, str(ex)), **result)
    except paramiko.SSHException as ex:
        module.fail_json(msg="failed to establish SSH connection: %s" % str(ex), **result)
    except Exception as ex:
        module.fail_json(msg="%s" % str(ex), **result)

    # Open SFTP (Secure-File-Transfer-Protocol) session between localhost
    # and remote server - on top of the established connection...
    sftp = connect.open_sftp()
    error_msg = None

    # -----------------------------------------------------------------

    # Upload / download the files:
    for file in files:
        try:
            stats = get_stats(sftp, file)

            if force or files_differ(stats):
                # We transfer files only when we are not in the 'check mode':
                if not module.check_mode:
                    transfer(sftp, file, stats, direction)

                result['changed'] = True

        except FileNotFoundError as ex:
            if direction == 'push':
                filepath = file['localpath']
            else:
                filepath = file['remotepath']

            error_msg = "file does not exist: %s" % filepath
            break

        except Exception as ex:
            error_msg = str(ex)
            break

    # -----------------------------------------------------------------

    # We need to make sure we terminate the SFTP session and the SSH2
    # connection properly - otherwise it might lead to partial transfers
    # or end-of-process hangs...
    # https://docs.paramiko.org/en/stable/api/client.html#paramiko.client.SSHClient.close

    # The sftp.close() closes both the SFTP session and the underlying
    # SSH2 connection...
    sftp.close()

    if error_msg:
        module.fail_json(msg=error_msg, **result)
    else:
        module.exit_json(**result)

# =====================================================================

def main():
    run_module()


if __name__ == '__main__':
    main()
