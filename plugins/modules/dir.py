#!/usr/bin/python

# Copyright: (c) 2023, Ryan Parker-Hill <ryanph@aspersion.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: ryanph.smbpath.dir

short_description: SMB directory management
version_added: "1.0.0"
description: Management of directories in SMB paths including complex ACLs

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
    paths:
        description:
            - The directory paths and corresponding ACLs to configure as a dictionary.
            - Path names (dictionary keys) are relative to the root of the SMB share.
        type: dictionary
        suboptions:
            owner:
                description:
                    - The name or SID representing the owner of the path
                type: string
            group:
                description:
                    - The name or SID representing the owning group of the path
                type: string
            acl:
                description:
                    - The ACL to apply (array)
                type: list
                elements:
                    type: dict
                    ace_type:
                        description:
                            - The ACE type (ALLOW or DENY)
                        type: string
                        choices:
                            - ALLOW
                            - DENY
                    target:
                        description:
                            - The SID or name representing the target of the ACE
                        type: string
                    flags:
                        description:
                            - An array of flags to apply to the ACE:
                            - SEC_ACE_FLAG_OBJECT_INHERIT
                            - SEC_ACE_FLAG_CONTAINER_INHERIT
                            - SEC_ACE_FLAG_NO_PROPAGATE_INHERIT
                            - SEC_ACE_FLAG_INHERIT_ONLY
                            - SEC_ACE_FLAG_INHERITED_ACE
                            - SEC_ACE_FLAG_VALID_INHERIT
                            - SEC_ACE_FLAG_SUCCESSFUL_ACCESS
                            - SEC_ACE_FLAG_FAILED_ACCESS
                        type: list
                    perms:
                        description:
                            - A list of permissions to apply:
                            - SEC_GENERIC_ALL
                            - SEC_GENERIC_EXECUTE
                            - SEC_GENERIC_WRITE
                            - SEC_GENERIC_READ
                            - SEC_FLAG_SYSTEM_SECURITY
                            - SEC_FLAG_MAXIMUM_ALLOWED
                            - SEC_STD_DELETE
                            - SEC_STD_READ_CONTROL
                            - SEC_STD_WRITE_DAC
                            - SEC_STD_WRITE_OWNER
                            - SEC_STD_SYNCHRONIZE
                            - SEC_STD_REQUIRED
                            - SEC_STD_ALL
                            - SEC_FILE_READ_DATA
                            - SEC_FILE_WRITE_DATA
                            - SEC_FILE_APPEND_DATA
                            - SEC_FILE_READ_EA
                            - SEC_FILE_WRITE_EA
                            - SEC_FILE_EXECUTE
                            - SEC_FILE_READ_ATTRIBUTE
                            - SEC_FILE_WRITE_ATTRIBUTE
                            - SEC_FILE_ALL
                            - SEC_DIR_LIST
                            - SEC_DIR_ADD_FILE
                            - SEC_DIR_ADD_SUBDIR
                            - SEC_DIR_READ_EA
                            - SEC_DIR_WRITE_EA
                            - SEC_DIR_TRAVERSE
                            - SEC_DIR_DELETE_CHILD
                            - SEC_DIR_READ_ATTRIBUTE
                            - SEC_DIR_WRITE_ATTRIBUTE
                            - SEC_RIGHTS_FILE_READ
                            - SEC_RIGHTS_FILE_WRITE
                            - SEC_RIGHTS_FILE_EXECUTE
                            - SEC_RIGHTS_FILE_ALL
                            - SEC_RIGHTS_DIR_READ
                            - SEC_RIGHTS_DIR_WRITE
                            - SEC_RIGHTS_DIR_EXECUTE
                            - SEC_RIGHTS_DIR_ALL
    state:
        description:
            - The desired state of the paths specified
        type: string
        choices:
            - absent
            - present
        default: present

author:
    - Ryan Parker-Hill (@ryanph)
'''

EXAMPLES = r'''
    - name: Create two directories
      ryanph.smbpath.dir:
        smb_hostname: 192.168.1.1
        smb_username: "DOMAIN\\user"
        smb_password: user_password
        smb_sharename: my_share
        paths:
          directory_one:
            owner: "DOMAIN\\user"
            group: "DOMAIN\\group"
            acl:
              - type: ALLOW
                target: "DOMAIN\\user_or_group"
                flags:
                  - SEC_ACE_FLAG_OBJECT_INHERIT
                  - SEC_ACE_FLAG_CONTAINER_INHERIT
                  - SEC_ACE_FLAG_INHERIT_ONLY
                perm:
                  - SEC_RIGHTS_DIR_ALL
          directory_one/subfolder:
            owner: "DOMAIN\\user"
            group: "DOMAIN\\group"
            acl:
              - type: ALLOW
                target: "DOMAIN\\user_or_group"
                flags:
                  - SEC_ACE_FLAG_OBJECT_INHERIT
                  - SEC_ACE_FLAG_CONTAINER_INHERIT
                  - SEC_ACE_FLAG_INHERIT_ONLY
                perm:
                  - SEC_RIGHTS_DIR_ALL
'''

RETURN = r'''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.errors import AnsibleError
import smbc
import sys

from ansible.collections.ryanph.smbdir.plugins.module_utils.security import dump_acl, build_acl_str_r1, conv_acl_to_int

def run_module():
    
    module_args = dict(
        smb_username=dict(type='str', required=False),
        smb_password=dict(type='str', required=False, no_log=True),
        smb_hostname=dict(type='str', required=True),
        smb_sharename=dict(type='str',required=True),
        paths=dict(type='dict',required=True),
        state=dict(type='str', required=False, default='present'),
        check_mode=dict(type='bool',default=False)
    )

    result = dict(
        changed=False,
        original_message='',
        message='',
        changes=[],
        paths={}
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # Connect to SMB Host
    def auth_fn(server, share, workgroup, username, password):
        return("", module.params['smb_username'], module.params['smb_password'])    
    ctx = smbc.Context(auth_fn=auth_fn)

    if module.params['state'] == 'present':

        # Iterate over paths, shortest path to longest, to support tree creation
        for path in sorted(module.params['paths'].keys(), key=len):

            if path.startswith("/"):
                path = path[1:]

            smb_uri = "smb://{}/{}/{}".format(
                module.params['smb_hostname'],
                module.params['smb_sharename'],
                path
            )

            # Create the path
            if not module.check_mode:
                try:
                    ctx.mkdir(smb_uri)
                    result['changed'] = True
                    result['changes'].append("Created {}".format(smb_uri))
                except smbc.ExistsError:
                    pass

            # Generate the desired extended attributes value
            d_xattr = build_acl_str_r1(
                module.params['paths'][path]['owner'],
                module.params['paths'][path]['group'],
                module.params['paths'][path]['acl']
            )

            # Fetch the configured extended attributes of the specified path
            try:
                c_xattr = ctx.getxattr(smb_uri, smbc.XATTR_ALL_SID)
            except smbc.NoEntryError:
                if module.check_mode:
                    result['changed'] = True
                    result['changes'].append("Would create {} and set ACL {}".format(
                        smb_uri, d_xattr
                    ))
                    continue
                else:
                    raise AnsibleError("Directory {} was created without error but is not visible".format(
                        smb_uri
                    ))

            # Compare and update extended attributes if required
            if c_xattr != d_xattr:
                if module.check_mode:
                    result['changed'] = True
                    result['changes'].append("Would set ACL on {} to {} (from {})".format(
                        smb_uri, d_xattr, c_xattr
                    ))
                else:
                    try:
                        ctx.setxattr(smb_uri,
                                smbc.XATTR_ALL_SID,
                                conv_acl_to_int(d_xattr),
                                smbc.XATTR_FLAG_REPLACE
                                )
                    except ValueError:
                        raise AnsibleError("Failed to apply ACL {}. ".format(d_xattr) +
                                           "This usually means an identifier is unresolvable or incorrect. " +
                                           "Please check all identifiers and try again.")
                    result['changed'] = True
                    result['changes'].append("Set ACL on {} to {} (from {})".format(
                        smb_uri, d_xattr, c_xattr
                    ))
                    c_xattr = ctx.getxattr(smb_uri, smbc.XATTR_ALL_SID)

            result['paths'][path] = dump_acl(c_xattr)

    elif module.params['state'] == 'absent':

        # Iterate over paths, shortest longest to shortest, to support tree removal
        for path in sorted(module.params['paths'].keys(), key=len, reverse=True):

            if path.startswith("/"):
                path = path[1:]

            smb_uri = "smb://{}/{}/{}".format(
                module.params['smb_hostname'],
                module.params['smb_sharename'],
                path
            )

            try:
                ctx.rmdir(smb_uri)
                result['changed'] = True
                result['changes'].append("Deleted {}".format(smb_uri))
            except smbc.NotEmptyError:
                raise AnsibleError("Cannot delete directory {} (not empty)".format(smb_uri))
            except ValueError:
                raise AnsibleError("Cannot delete directory {} (in use)".format(smb_uri))
            except smbc.NoEntryError:
                # Directory already absent
                pass

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()