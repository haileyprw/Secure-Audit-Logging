from time import time
from logging import print_to_log

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
    # handle invalid subject/object/action, potentially seperate log entry for malformed requests
    if (sub not in subjects):
        print_to_log("Invalid subject: " + sub + " attempted to " + action + " " + obj)
        return (False, sub, obj, action)
    if (obj not in objects):
        print_to_log("Invalid object: " + sub + " attempted to " + action + " " + obj)
        return (False, sub, obj, action)
    if (action not in RIGHTS):
        print_to_log("Invalid action: " + sub + " attempted to " + action + " " + obj)
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
        print_to_log(sub + " attempted to " + action + " the following read-only file: " + obj)
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
    print_to_log("Denied action: " + sub + " tried to " + action + " " + obj)
    return (False, sub, obj, action)

# Assigns role to subject
# str sub: subject being assigned to
# str role: role being assigned
# Return: True if success, False if invalid role or already assigned identical role
def assign_role(sub, role):
    if role not in ROLES:
        # log malformed role
        print_to_log("Malformed role: " + role + " given to " + sub)
        return False
    
    if sub not in subjects:
        # log malformed subject
        print_to_log("Malformed subject: " + role + " given to " + sub)
        return False
    
    if rbac_assignment_pairs.get(sub) == role:
        # log redundant role assignment
        print_to_log("Redundant role assignment: " + role + " given to " + sub)
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
    # handle invalid subject/object/action, potentially seperate log entry for malformed requests
    if (sub not in subjects):
        print_to_log("Invalid subject: " + permission + " not given to " + sub + " on " + obj)
        pass
    if (obj not in objects):
        print_to_log("Invalid object: " + permission + " not given to " + sub + " on " + obj)
        pass
    if (permission not in RIGHTS and permission != 'OWN'):
        print_to_log("Invalid right: " + permission + " not given to " + sub + " on " + obj)
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
        # log attempted redundant permission grant request
        print_to_log("Redundant permission: " + permission + " not given to " + sub + " on " + obj)
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
    



# Test cases:
# Anything that says granted should not show up in the log, everything that says denied should be seen in log
# Admin
check_authorization("JANE", "something.doc", "READ") # granted
check_authorization("JANE", "something.doc", "WRITE") # granted
check_authorization("JANE", "something.doc", "EXECUTE") # granted
check_authorization("JANE", "something.doc", "SHARE") # granted

# Auditor 
check_authorization("JOE", "something.doc", "READ") # granted
check_authorization("JOE", "something.doc", "WRITE") # denied
check_authorization("JOE", "something.doc", "EXECUTE") # denied
check_authorization("JOE", "something.doc", "SHARE") # denied

# User
check_authorization("JOHN", "something.doc", "READ") # denied
check_authorization("JOHN", "something.doc", "WRITE") # denied
check_authorization("JOHN", "something.doc", "EXECUTE") # denied
check_authorization("JOHN", "something.doc", "SHARE") # denied

# Grant test
grant_permission("JOHN", "something.doc", "READ", 10)
check_authorization("JOHN", "something.doc", "READ") # granted

# Malformed grants
grant_permission("JOHN", "something.doc", "REA", 10) # denied
grant_permission("JOHN", "something.do", "EXECUTE", 10) # denied
grant_permission("JOH", "something.doc", "EXECUTE", 10) # denied

# Malformed authorization
check_authorization("JAN", "something.doc", "READ") # denied
check_authorization("JANE", "something.do", "READ") # denied
check_authorization("JANE", "something.doc", "REA") # denied

# Read-only test
check_authorization("JANE", "log.txt", "READ") # granted
check_authorization("JOE", "log.txt", "READ") # granted
check_authorization("JANE", "log.txt", "WRITE") # denied
check_authorization("JANE", "log.txt", "EXECUTE") # denied
check_authorization("JANE", "log.txt", "SHARE") # denied
check_authorization("JOE", "log.txt", "WRITE") # denied
check_authorization("BOB", "log.txt", "WRITE") # denied