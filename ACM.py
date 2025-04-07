from time import time
from logging import print_to_log

#Hybrid RBAC & DAC
#Roles override discretionary access
#discretionary access allows users to control permissions over owned files

#
# Constants
#

#Roles that subjects can possess
ROLES = ['ADMIN', 'AUDITOR', 'USER']

#Actions that subjects can exercise over objects
#NOTE: While 'OWN' is not included here, 'OWN' can be a defined right for a dac_permission_pair entry, it cannot be evaluated with check_authorization, but ownership can be verified with the is_owner function
RIGHTS = ['READ', 'WRITE', 'EXECUTE', 'SHARE']

#The absolute rights that are guaranteed to subjects with this role over ALL objects (except for those in the UNIVERSAL_READ_ONLY category)
ROLE_DEFAULT_RIGHTS = {
    'ADMIN': ['READ', 'WRITE', 'EXECUTE', 'SHARE'],
    'AUDITOR': ['READ'], 
    'USER': []
}

#Objects listed here cannot have any right exercised over them other than 'READ' regardless of dac or rbac evaluation
UNIVERSAL_READ_ONLY = ['log.txt']

#Example of general ACM structure
EXAMPLE_ACM = {'subjects': ['JANE', 'JOE', 'BOB', 'JOHN'], 
               'objects': ['log.txt', 'photo.jpg', 'something.doc'], 
               'dac_permission_pairs': [], 
               'rbac_assignment_pairs': {'JANE': 'ADMIN', 'JOE': 'AUDITOR', 'BOB': 'USER', 'JOHN': 'USER'}}

#dac_permission_pairs takes the form a tuple (subject, object, right, expiry)
#where expiry is an OPTIONAL duration of seconds the pair is active for
#rbac_permission_pairs takes the form of a dictionary entry {"subject": "role"}

# Checks the authorization of a subject over some object performing some action
# dict ACM: Access control dictionary
# str sub: Subject to be evaluated
# str obj: Object to be evaluated
# str action: Action/Right to be invoked
# Returns tuple with following format:
# (Boolean whether granted, sub, obj, action)
def check_authorization(ACM, sub, obj, action):
    #extract needed data from ACM 
    subjects = ACM.get('subjects')
    objects = ACM.get('objects')
    rbac_assignment_pairs = ACM.get("rbac_assignment_pairs")
    dac_permission_pairs = ACM.get("dac_permission_pairs")

    #validity check
    # handle invalid subject/object/action, potentially separate log entry for malformed requests
    if (sub not in subjects):
        print_to_log(f"Invalid subject: {sub} attempted to {action} {obj}")
        return (False, sub, obj, action)
    if (obj not in objects):
        print_to_log(f"Invalid object: {sub} attempted to {action} {obj}")
        return (False, sub, obj, action)
    if (action not in RIGHTS):
        print_to_log(f"Invalid right: {sub} attempted to {action} {obj}")
        return (False, sub, obj, action)

    #grab role for later use
    SUB_ROLE = rbac_assignment_pairs.get(sub)

    #grab default role permissions
    DEFAULT_ROLE_PERMISSIONS = ROLE_DEFAULT_RIGHTS.get(SUB_ROLE)

    #grab relevant access pairs for user, object, and action (using list comprehension)
    permission_pairs = [i for i in dac_permission_pairs if (i[0] == sub and i[1] == obj and i[2] == action)]

    CURRENT_TIME = time()

    #remove expired access pairs if needed
    for pair in [i for i in permission_pairs if (len(i) == 4) and i[3] < CURRENT_TIME]:
        permission_pairs.remove(pair)
        dac_permission_pairs.remove(pair)

    #check universal read only
    if (obj in UNIVERSAL_READ_ONLY and action != "READ"):
        # log attempted non-read action of read-only file (can technically be done outside of this function using the tuple)
        print_to_log(f"{sub} attempted to {action} the following read-only file: {obj}")
        return (False, sub, obj, action)

    #check default role
    if (action in DEFAULT_ROLE_PERMISSIONS):
        # Default permission is not logged, however it could be
        return (True, sub, obj, action)
    
    #check DAC permissions
    if (len(permission_pairs) > 0):
        return (True, sub, obj, action)
    
    #default
    # log attempted action
    print_to_log(f"Denied action: {sub} tried to {action} {obj}")
    return (False, sub, obj, action)

# Assigns role to subject
# str sub: subject being assigned to
# str role: role being assigned
# Return: True if success, False if invalid role or already assigned identical role
def assign_role(ACM, sub, role):
    subjects = ACM.get('subjects')
    rbac_assignment_pairs = ACM['rbac_assignment_pairs']

    if role not in ROLES:
        # log malformed role
        print_to_log(f"Malformed role: {role}  given to {sub}")
        return False
    
    if sub not in subjects:
        # log malformed subject
        print_to_log(f"Malformed subject: {role} given to {sub}")
        return False
    
    if rbac_assignment_pairs.get(sub) == role:
        # log redundant role assignment
        print_to_log(f"Redundant role assignment: {role} given to {sub}")
        return False
    
    rbac_assignment_pairs[sub] = role
    return True

# Creates and appends a new dac-based permission pair
# dict ACM: Access control dictionary
# str sub: subject to create pair for
# str obj: object that subject is to have right for
# str permission: the permission to be granted in this request
# int expiry: time in seconds that this pair will be valid/active for
# Return: True if permission granted, False if not (for any reason)
def grant_permission(ACM, sub, obj, permission, expiry=0):
    subjects = ACM.get('subjects')
    objects = ACM.get('objects')
    dac_permission_pairs = ACM['dac_permission_pairs']

    #validity check
    # handle invalid subject/object/action, potentially seperate log entry for malformed requests
    if (sub not in subjects):
        print_to_log(f"Invalid subject: {permission} not given to {sub} on {obj}")
        return False
    if (obj not in objects):
        print_to_log(f"Invalid object: {permission} not given to {sub} on {obj}")
        return False
    if (permission not in RIGHTS and permission != 'OWN'):
        print_to_log(f"Invalid right: {permission} not given to {sub} on {obj}")
        return False

    #Permanent non-expiring entry indicating by expiry default value of 0 (seconds)
    if expiry == 0:
        pair = (sub, obj, permission)
    else:
        expiry += time()
        pair = (sub, obj, permission, expiry)

    if (pair not in dac_permission_pairs):
        dac_permission_pairs.append(pair)
        return True
    else:
        # log attempted redundant permission grant request
        print_to_log(f"Redundant permission: {permission} not given to {sub} on {obj}")
        return False

# Removes all entries of matching parameters from dac_permission_pairs
# dict ACM: Access control dictionary
# str sub: subject to remove
# str obj: object to remove
# str permission: permission to remove
def revoke_permission(ACM, sub, obj, permission):
    dac_permission_pairs = ACM.get('dac_permission_pairs')
    ACM['dac_permission_pairs'] = [p for p in dac_permission_pairs if not (p[0] == sub and p[1] == obj and p[2] == permission)]

# Checks if sub is owner of obj, takes into account owner permission with expiry
# dict ACM: Access control dictionary
# str sub: subject to check
# str obj: object to check
# Return: True if owner, False if not owner
def is_owner(ACM, sub, obj):
    dac_permission_pairs = ACM.get('dac_permission_pairs')

    matching_pairs = [p for p in dac_permission_pairs if (p[0] == sub and p[1] == obj and p[2] == 'OWN')]
    if len(matching_pairs) >= 1:
        for pair in matching_pairs:
            #check for expiry flag on pair
            if len(pair) == 4:
                if (pair[3] > time()):
                    return True
            else:
                return True
    else:
        return False