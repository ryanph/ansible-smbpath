#!/usr/bin/python

# Copyright: (c) 2023, Ryan Parker-Hill <ryanph@hoover.rocks>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: ryanph.smbpath.file

short_description: SMB file or directory rename / move
version_added: "1.2.0"

description: SMB file or directory rename / move. Successful if the path is renamed, or the old path does not exist AND the new path exists.

options:
    smb_hostname:
        description:
            - The hostname or IP address of the SMB server to connect to
        type: string
        required: True
    smb_username:
        description:
            - The username to authenticate with when connecting to the SMB server
        type: string
        required: True
    smb_password:
        description:
            - The password to authenticate with when connecting to the SMB server
        type: string
        required: True
    smb_sharename:
        description:
            - The name of the SMB share to connect to
        type: string
        required: True
    ignore_ace_order:
        description:
            - Whether to ignore the order of ACL Entries in comparison.
        type: boolean
        default: True
    old_path:
        description:
            - The path to the source file or directory relative to the root of the SMB share
    new_path:
        description:
            - The new path relative to the root of the SMB share
author:
    - Ryan Parker-Hill (@ryanph)
'''

EXAMPLES = r'''
-   name: Rename a file
    ryanph.smbpath.rename:
        smb_hostname: 192.168.1.1
        smb_username: "DOMAIN\\user"
        smb_password: user_password
        smb_sharename: my_share
        old_path: file_one
        new_path: file_two

'''

RETURNs = r'''
    changed: True
    changes:
        - "Renamed smb://192.168.1.1/my_share/file_one to smb://192.168.1.1/my_share/file_two"
    path: <acl_object>
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.errors import AnsibleError
import smbc
import os

def run_module():
    
    module_args = dict(
        smb_username=dict(type='str', required=False),
        smb_password=dict(type='str', required=False, no_log=True),
        smb_hostname=dict(type='str', required=True),
        smb_sharename=dict(type='str',required=True),
        old_path=dict(type='str', required=True),
        new_path=dict(type='str', required=True),
        check_mode=dict(type='bool', default=False)
    )

    result = dict(
        changed=False,
        changes=[]
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
    )

    # Setup Context
    def auth_fn(server, share, workgroup, username, password):
        return("", module.params['smb_username'], module.params['smb_password'])    
    ctx = smbc.Context(auth_fn=auth_fn)

    # Stat the root of the share to test the connection
    smb_uri = "smb://{}/{}".format(
        module.params['smb_hostname'],
        module.params['smb_sharename']
    )
    try:
        ctx.stat(smb_uri)
    except ValueError as e:
        raise AnsibleError("Could not connect to share \"{}\" {}".format(smb_uri, e))
    except smbc.PermissionError as e:
        raise AnsibleError("Could not connect to share \"{}\" as {} {}".format(
            smb_uri, module.params['smb_username'], e))
    except smbc.NoEntryError as e:
        raise AnsibleError("Could not connect to share \"{}\" on host \"{}\" {}".format(
            module.params['smb_sharename'],module.params['smb_hostname'], e))

    # Generate URIs
    new_path = module.params['new_path']
    if new_path.startswith("/"):
        new_path = new_path[1:]
    new_uri = "smb://{}/{}/{}".format(
        module.params['smb_hostname'],
        module.params['smb_sharename'],
        new_path
    )

    old_path = module.params['old_path']
    if old_path.startswith("/"):
        old_path = old_path[1:]
    old_uri = "smb://{}/{}/{}".format(
        module.params['smb_hostname'],
        module.params['smb_sharename'],
        old_path
    )
    
    # Stat both the old and new paths
    new_path_stat = None
    try:
        new_path_stat = ctx.stat(new_uri)
    except smbc.NoEntryError:
        pass
    except Exception as e:
        raise AnsibleError("An unhandled exception occurred while checking if {} exists {}".format(
            new_uri, e
        ))

    old_path_stat = None
    try:
        old_path_stat = ctx.stat(old_uri)
    except smbc.NoEntryError:
        pass
    except Exception as e:
        raise AnsibleError("An unhandled exception occurred while checking if {} exists {}".format(
            old_uri, e
        ))

    # Do the needful
    if new_path_stat is None and old_path_stat is not None:
        if module.params['check_mode']:
            result['changes'].append("Would have moved {} to {}".format(old_uri, new_uri))
            result['changed'] = True 
        else:
            try:
                ctx.rename(old_uri, new_uri)
            except Exception as e:
                raise AnsibleError("An unhandled exception occurred while renaming {} to {} {}".format(
                    old_uri, new_uri, e
                ))
            result['changes'].append("Moved {} to {}".format(old_uri, new_uri))
            result['changed'] = True
    elif new_path_stat is not None and old_path_stat is None:
        pass
    elif new_path_stat is not None and old_path_stat is not None:
        raise AnsibleError("Both the old path and new path specified already exist")
    else:
        raise AnsibleError("Neither the old path or new path specified exist")

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()
