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

description: Management of directories in SMB paths with complex ACL support

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
    ignore_errors:
        description:
            - Whether to ignore errors when creating directories or setting ACLs.
            - Errors will instead be returned in an 'errors' property.
        type: boolean
        default: False
    ignore_ace_order:
        description:
            - Whether to ignore the order of ACL Entries in comparison.
        type: boolean
        default: True
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
    remove_temp_files:
        description:
            - When deleting a folder (state is absent) delete any files in the directory that match well known resource fork and temporary filenames (Thumbs.db, .DS_Store etc)
        type: boolean
        default: True    
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
                        - ace_type: ALLOW
                          target: "DU\\user_or_group"
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
                        - ace_type: ALLOW
                          target: "DOMAIN\\user_or_group"
                          flags:
                            - SEC_ACE_FLAG_OBJECT_INHERIT
                            - SEC_ACE_FLAG_CONTAINER_INHERIT
                            - SEC_ACE_FLAG_INHERIT_ONLY
                          perm:
                            - SEC_RIGHTS_DIR_ALL
'''

RETURNs = r'''
    changed: True
    changes:
        - "Created smb://192.168.1.1/my_share/directory_one"
        - "Set ACL on smb://192.168.1.1/my_share/directory_one to ..."
        - "Created smb://192.168.1.1/my_share/directory_one/subfolder"
        - "Set ACL on smb://192.168.1.1/my_share/directory_one/subfolder to ..."
    paths:
        directory_one: <acl object>
        directory_one/subfolder: <acl object>
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.errors import AnsibleError
import smbc
import re

from ansible_collections.ryanph.smbpath.plugins.module_utils.security import dump_acl, build_acl_str_r1, conv_acl_to_int, diff_acl

def run_module():
    
    module_args = dict(
        smb_username=dict(type='str', required=False),
        smb_password=dict(type='str', required=False, no_log=True),
        smb_hostname=dict(type='str', required=True),
        smb_sharename=dict(type='str',required=True),
        ignore_errors=dict(type='bool', default=False),
        ignore_ace_order=dict(type='bool', default=True),
        paths=dict(type='dict', required=True),
        state=dict(type='str', required=False, default='present'),
        check_mode=dict(type='bool', default=False),
        remove_temp_files=dict(type='bool', default=True)
    )

    result = dict(
        changed=False,
        changes=[],
        errors=[],
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
                except Exception as e:
                    raise AnsibleError("An error occurred while creating {}: {}".format(smb_uri, e))

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
            diffs = diff_acl(c_xattr, d_xattr, module.params['ignore_ace_order'])
            if diffs != None:
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
                        if module.params['ignore_errors']:
                            result['errors'].append("Failed to apply ACL {} to {}. ".format(d_xattr, smb_uri))
                            continue
                        raise AnsibleError("Failed to apply ACL {} to {}. ".format(d_xattr, smb_uri) +
                                           "This usually means an identifier is unresolvable or incorrect. " +
                                           "Please check all identifiers and try again.")
                    except Exception as e:
                        raise AnsibleError("An unhandled exception occurred while setting ACL {} on file {} {}".format(
                            d_xattr, smb_uri, e
                        ))
                    result['changed'] = True
                    result['changes'].append("Set ACL on {} to {} (from {})".format(
                        smb_uri, d_xattr, c_xattr
                    ))

                    try:
                        c_xattr = ctx.getxattr(smb_uri, smbc.XATTR_ALL_SID)
                    except Exception as e:
                        raise AnsibleError("An unhandled exception occurred while fetching extended attributes of {} {}".format(
                            smb_uri, e
                        ))

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

            # Check if the directory is empty, delete temporary files if requested
            tempfile_regexes = [
                '\.DS_Store$',
                '\._.*$',
                'Thumbs.db$',
                '~\$.+$'
            ]
            if module.params['remove_temp_files']:
                files = []
                try:
                    files = ctx.opendir(smb_uri).getdents()
                except smbc.NoEntryError:
                    # Directory already absent
                    pass
                except Exception as e:
                    raise AnsibleError(" contents of {} {}".format(smb_uri, e))

                for file in files:
                    for rex in tempfile_regexes:
                        if re.match(rex, file.name):
                            file_path = "{}/{}".format(smb_uri, file.name)
                            try:
                                ctx.unlink(file_path)
                                result['changes'].append("Deleted {}".format(file_path))
                            except Exception as e:
                                raise AnsibleError("Attempt to delete temprary file {} failed {}".format(
                                    file_path, e
                                ))

            try:
                ctx.rmdir(smb_uri)
                result['changed'] = True
                result['changes'].append("Deleted {}".format(smb_uri))
            except smbc.NotEmptyError:
                raise AnsibleError("Cannot delete directory {} as it is not empty".format(smb_uri))
            except ValueError:
                raise AnsibleError("Cannot delete directory {} (in use)".format(smb_uri))
            except smbc.NoEntryError:
                # Directory already absent
                pass
            except Exception as e:
                raise AnsibleError("An unhandled exception occurred while attempting to delete {} {}".format(
                    smb_uri, e
                ))

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()
