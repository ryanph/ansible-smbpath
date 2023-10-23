# Ansible Collection - ryanph.smbpath

Management of directories in SMB shares including complex ACLs.

## Requirements

* [pysmbc](https://pypi.org/project/pysmbc/) and its dependencies

## Installation

```
pip3 install pysmbc
ansible-galaxy collection install https://github.com/ryanph/ansible-smbpath/releases/download/v1.0.2/ryanph-smbpath-1.0.2.tar.gz
```

## Module Summary

```
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
  state:
    description:
      - The desired state of the paths specified
    type: string
    choices:
      - absent
      - present
    default: present
```

### Examples

```
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
```