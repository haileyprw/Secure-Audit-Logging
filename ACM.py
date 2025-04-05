from time import time

#Hybrid RBAC & DAC
#Roles override discretionary access
#discretionary access allows users to control permissions over owned files

#Constant roles and rights definitions
ROLES = ['ADMIN', 'AUDITOR', 'USER']
RIGHTS = ['READ', 'WRITE', 'EXECUTE', 'SHARE']

#NOTE: The method through which read-access is granted to audit log is through "AUDITOR" role, however this also applies universally to all other objects..

#Default rights that a given role gets REGARDLESS of dac permissions
ROLE_DEFAULT_RIGHTS = {
    'ADMIN': ['READ', 'WRITE', 'EXECUTE', 'SHARE'],
    'AUDITOR': ['READ'], 
    'USER': []
}

UNIVERSAL_READ_ONLY = ['log.txt']

subjects = ['JANE', 'JOE', 'BOB', 'JOHN']
objects = ['log.txt', 'photo.jpg', 'something.doc']


#ACM STRUCTURE
#dac_permission_pairs are of format (user, object, permission, expiry_time_seconds)
#NOTE: OWN is a valid entry for 'permission' here even though it is not listed in the RIGHTS
#rbac_assignment_pairs are of format {'SUBJECTS': 'ROLE'}
dac_permission_pairs = []
rbac_assignment_pairs = {'JANE': 'ADMIN', 'JOE': 'AUDITOR', 'BOB': 'USER', 'JOHN': 'USER'}

# Checks the authorization of a subject over some object performing some action
# str sub: Subject to be evaluated
# str obj: Object to be evaluated
# str action: Action/Right to be invoked
# Returns tuple with following format:
# (Boolean whether granted, sub, obj, action)
def check_authorization(sub, obj, action):
    #validity check
    #TODO: handle invalid subject/object/action, potentially seperate log entry for malformed requests
    if (sub not in subjects):
        pass
    if (obj not in objects):
        pass
    if (action not in RIGHTS):
        pass

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
        #TODO: log attempted non-read action of read-only file (can technically be done outside of this function using the tuple)
        return (False, sub, obj, action)

    #check default role
    if (action in DEFAULT_ROLE_PERMISSIONS):
        #TODO: Decide whether to log actions that are performed with default permissions from roles
        return (True, sub, obj, action)
    
    #check DAC permissions
    if (len(permission_pairs) > 0):
        return (True, sub, obj, action)
    
    #default
    #TODO: log attempted action
    return (False, sub, obj, action)

# Assigns role to subject
# str sub: subject being assigned to
# str role: role being assigned
# Return: True if success, False if invalid role or already assigned identical role
def assign_role(sub, role):
    if role not in ROLES:
        #TODO: Potentially log malformed role
        return False
    
    if sub not in subjects:
        #TODO: Potentially log malformed subject
        return False
    
    if rbac_assignment_pairs.get(sub) == role:
        #TODO: Potentially log redundant role assignment
        return False
    
    rbac_assignment_pairs[sub] = role
    return True

# Creates and appends a new dac-based permission pair
# str sub: subject to create pair for
# str obj: object that subject is to have right for
# str permission: the permission to be granted in this request
# int expiry: time in seconds that this pair will be valid/active for
def grant_permission(sub, obj, permission, expiry=0):
    #validity check
    #TODO: handle invalid subject/object/action, potentially seperate log entry for malformed requests
    if (sub not in subjects):
        pass
    if (obj not in objects):
        pass
    if (permission not in RIGHTS and permission != 'OWN'):
        pass

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
        #TODO: potentially log attempted redundant permission grant request
        return False

# Removes all entries of matching parameters from dac_permission_pairs
# str sub: subject to remove
# str obj: object to remove
# str permission: permission to remove
def revoke_permission(sub, obj, permission):
    global dac_permission_pairs
    dac_permission_pairs = [p for p in dac_permission_pairs if not (p[0] == sub and p[1] == obj and p[2] == permission)]

# Checks if sub is owner of obj, takes into account owner permission with expiry
# str sub: subject to check
# str obj: object to check
# Return: True if owner, False if not owner
def is_owner(sub, obj):
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