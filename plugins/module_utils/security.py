#!/usr/bin/env python3

def blank_acl():

    # Return a blank ACL data structure
    return {
        "revision": 1,
        "owner": "",
        "group": "",
        "acl": []
    }

def build_acl_str_r1(owner, group, aces=[]):
    
    # Take an ACL object and convert it to an xattr string

    acl = "REVISION:1,OWNER:{},GROUP:{},".format(
        owner, group
    )

    conv_aces = []
    for ace in aces:
        conv_aces.append(build_ace_str(
            ace['target'],
            ace['ace_type'],
            ace['flags'],
            ace['perm']
        ))
    acl += ",".join(conv_aces)

    return acl


def build_ace_str(target, ace_type, flags=[], perms=[]):

    # Take an individual ACE and build it into a xattr string

    ace = "ACL:{}:".format(target)
    if isinstance(ace_type, int):
        ace += "{}/".format(ace_type)
    else:
        if ace_type == 'ALLOW':
            ace += "0/"
        elif ace_type == 'DENY':
            ace += "1/"
        else:
            raise Exception("Unexpected ace_type specified: {}".format(ace_type))

    flag_val = 0
    for flag in flags:
        if flag not in ace_flags_map:
            raise Exception("Unknown ACE flag specified in ACE: {}".format(flag))
        flag_val = flag_val | ace_flags_map[flag]
    ace += str(int(flag_val)) + "/"

    perms_val = 0
    for perm in perms:
        if perm in sec_bits_map.keys():
            perms_val = perms_val | sec_bits_map[perm]
        elif perm in role_map.keys():
            perms_val = perms_val | role_map[perm]
        else:
            raise Exception("Unexpected ACE permission specified: {}".format(perm))
    ace += "{0:#010x}".format(perms_val)
    return ace

def dump_ace(ace, dir=True):
    
    # Take an individual ACE and dump it into a human readable data structure

    if not ace.startswith('ACL:'):
        raise Exception('Unexpected prefix in ACL entry {}'.format(ace))
    
    parts = ace.split('/')
    sec = {
        'ace_type':   '',
        'target': ace.split(':')[1],
        'flags':  [],
        'perm':   []
    }

    ace_type = int(parts[0].split(':')[2])
    if ace_type == 0:
        sec['ace_type'] = 'ALLOW'
    elif ace_type == 1:
        sec['ace_type'] = 'DENY'
    else:
        raise Exception('Unknown ace_type specified {} (expected 0 or 1)'.format(ace_type))

    flags = int(parts[1])
    for flag in ace_flags_map.keys():
        if flags & ace_flags_map[flag] == ace_flags_map[flag]:
            sec['flags'].append(flag)

    caps = int(parts[-1], 0)
    for cap in sec_bits_map.keys():
        if caps & sec_invalid_bits: # This doesn't do what you think it does
            raise Exception('ACE has invalid bits set')
        if dir and not cap.startswith('SEC_FILE') or not dir and cap.startswith('SEC_DIR'):
            if caps & sec_bits_map[cap] == sec_bits_map[cap]:
                sec['perm'].append(cap)
    for role in role_map.keys():
        if caps & role_map[role] == role_map[role]:
            sec['perm'].append(role)

    return sec

def dump_acl(acl):

    # Take an ACL string and convert it into a human readable data structure
    
    ret = blank_acl()
    for ace in acl.split(','):
        if ace.startswith('REVISION:'):
            ret['revision'] = int(ace.split(':')[1])
        elif ace.startswith('OWNER:'):
            ret['owner'] = ace.split(':')[1]
        elif ace.startswith('GROUP:'):
            ret['group'] = ace.split(':')[1]
        elif ace.startswith('ACL:'):            
            ret['acl'].append(dump_ace(ace))
        else:
            raise Exception('Unknown prefix in ACL entry "{}"'.format(ace))
    
    return ret

def conv_ace_to_int(ace):

    # Take an individual ace with a hex mask and convert it to an integer

    if ace.startswith('ACL'):
        parts = ace.split('/')
        return "{}/{}".format("/".join(parts[:-1]), int(str(parts[-1]),0))
    else:
        return ace

def conv_acl_to_int(acl):

    # Convert all ACE masks in an ACL into integer format for setting with setxattr

    new_acl = []
    for ace in acl.split(','):
        new_acl.append(conv_ace_to_int(ace))
    return ','.join(new_acl)


# References:
# https://github.com/samba-team/samba/blob/master/librpc/idl/security.idl
# https://github.com/hamano/pysmbc/blob/master/smbc/xattr.py

mask_map = {
    'SEC_MASK_GENERIC'  : 0xF0000000,
    'SEC_MASK_FLAGS'    : 0x0F000000,
    'SEC_MASK_STANDARD' : 0x00FF0000,
    'SEC_MASK_SPECIFIC' : 0x0000FFFF
}

ace_flags_map = {
    'SEC_ACE_FLAG_OBJECT_INHERIT'       : 0x01,
	'SEC_ACE_FLAG_CONTAINER_INHERIT'	: 0x02,
	'SEC_ACE_FLAG_NO_PROPAGATE_INHERIT'	: 0x04,
	'SEC_ACE_FLAG_INHERIT_ONLY'		    : 0x08,
	'SEC_ACE_FLAG_INHERITED_ACE'		: 0x10,
	'SEC_ACE_FLAG_VALID_INHERIT'		: 0x0f,
	'SEC_ACE_FLAG_SUCCESSFUL_ACCESS'	: 0x40,
	'SEC_ACE_FLAG_FAILED_ACCESS'		: 0x80
}

sec_invalid_bits = 0x0ce0fe00
sec_bits_map = {
    
    # Generic Bits
    'SEC_GENERIC_ALL'     : 0x10000000,
    'SEC_GENERIC_EXECUTE' : 0x20000000,
    'SEC_GENERIC_WRITE'   : 0x40000000,
    'SEC_GENERIC_READ'    : 0x80000000,

    # Flags
    'SEC_FLAG_SYSTEM_SECURITY' : 0x01000000,
    'SEC_FLAG_MAXIMUM_ALLOWED' : 0x02000000,

    # Standard Bits
	'SEC_STD_DELETE'       : 0x00010000,
	'SEC_STD_READ_CONTROL' : 0x00020000,
	'SEC_STD_WRITE_DAC'    : 0x00040000,
	'SEC_STD_WRITE_OWNER'  : 0x00080000,
	'SEC_STD_SYNCHRONIZE'  : 0x00100000,
	'SEC_STD_REQUIRED'     : 0x000F0000,
	'SEC_STD_ALL'          : 0x001F0000,

    # File Specific Bits
	'SEC_FILE_READ_DATA'       : 0x00000001,
	'SEC_FILE_WRITE_DATA'      : 0x00000002,
	'SEC_FILE_APPEND_DATA'     : 0x00000004,
	'SEC_FILE_READ_EA'         : 0x00000008,
	'SEC_FILE_WRITE_EA'        : 0x00000010,
	'SEC_FILE_EXECUTE'         : 0x00000020,
	'SEC_FILE_READ_ATTRIBUTE'  : 0x00000080,
	'SEC_FILE_WRITE_ATTRIBUTE' : 0x00000100,
	'SEC_FILE_ALL'             : 0x000001ff,
        
    # Directory Specific Bits
	'SEC_DIR_LIST'             : 0x00000001,
	'SEC_DIR_ADD_FILE'         : 0x00000002,
	'SEC_DIR_ADD_SUBDIR'       : 0x00000004,
	'SEC_DIR_READ_EA'          : 0x00000008,
	'SEC_DIR_WRITE_EA'         : 0x00000010,
	'SEC_DIR_TRAVERSE'         : 0x00000020,
	'SEC_DIR_DELETE_CHILD'     : 0x00000040,
	'SEC_DIR_READ_ATTRIBUTE'   : 0x00000080,
	'SEC_DIR_WRITE_ATTRIBUTE'  : 0x00000100,

}

role_map = {
    'SEC_RIGHTS_FILE_READ': sec_bits_map['SEC_STD_READ_CONTROL'] | 
                            sec_bits_map['SEC_STD_SYNCHRONIZE'] |
                            sec_bits_map['SEC_FILE_READ_DATA'] | 
                            sec_bits_map['SEC_FILE_READ_ATTRIBUTE'] |
                            sec_bits_map['SEC_FILE_READ_EA'],

    'SEC_RIGHTS_FILE_WRITE':    sec_bits_map['SEC_STD_READ_CONTROL'] |
                                sec_bits_map['SEC_STD_SYNCHRONIZE'] |
                                sec_bits_map['SEC_FILE_WRITE_DATA'] |
                                sec_bits_map['SEC_FILE_WRITE_ATTRIBUTE'] |
                                sec_bits_map['SEC_FILE_WRITE_EA'] |
                                sec_bits_map['SEC_FILE_APPEND_DATA'],

    'SEC_RIGHTS_FILE_EXECUTE':  sec_bits_map['SEC_STD_SYNCHRONIZE'] |
                                sec_bits_map['SEC_STD_READ_CONTROL'] |
                                sec_bits_map['SEC_FILE_READ_ATTRIBUTE'] |
                                sec_bits_map['SEC_FILE_EXECUTE'],
    
    'SEC_RIGHTS_FILE_ALL':  sec_bits_map['SEC_STD_ALL'] | sec_bits_map['SEC_FILE_ALL'],

    'SEC_RIGHTS_DIR_READ':  sec_bits_map['SEC_STD_READ_CONTROL'] | 
                            sec_bits_map['SEC_STD_SYNCHRONIZE'] |
                            sec_bits_map['SEC_DIR_LIST'] | 
                            sec_bits_map['SEC_DIR_READ_ATTRIBUTE'] |
                            sec_bits_map['SEC_DIR_READ_EA'],

    'SEC_RIGHTS_DIR_WRITE':     sec_bits_map['SEC_STD_READ_CONTROL'] |
                                sec_bits_map['SEC_STD_SYNCHRONIZE'] |
                                sec_bits_map['SEC_DIR_ADD_FILE'] |
                                sec_bits_map['SEC_DIR_WRITE_ATTRIBUTE'] |
                                sec_bits_map['SEC_DIR_WRITE_EA'] |
                                sec_bits_map['SEC_DIR_ADD_SUBDIR'],

    'SEC_RIGHTS_DIR_EXECUTE':   sec_bits_map['SEC_STD_SYNCHRONIZE'] |
                                sec_bits_map['SEC_STD_READ_CONTROL'] |
                                sec_bits_map['SEC_DIR_READ_ATTRIBUTE'] |
                                sec_bits_map['SEC_DIR_TRAVERSE'],

    'SEC_RIGHTS_DIR_ALL':       sec_bits_map['SEC_STD_ALL'] | sec_bits_map['SEC_FILE_ALL']

}