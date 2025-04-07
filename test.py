from ACM import *
from time import sleep
import os
from logging import LOG_FILE_NAME

test_number = 1

if (os.path.exists(LOG_FILE_NAME)):
    with open(LOG_FILE_NAME, 'r') as l:
        log_line = len(l.readlines())+1
else:
    log_line = 1


def print_logged_tag(b):
    global log_line
    if not b:
        print(f"  LOGGED@{log_line:03}")
        log_line += 1
    else:
        print()
    return

def test_authorization(sub, obj, act, expected_result):
    global test_number
    result = check_authorization(EXAMPLE_ACM, sub, obj, act)[0]

    if result == expected_result:
        r_string = "PASSED"
    else:
        r_string = f"FAILED"
    print(f"{sub:^10} | {obj:^18} | {act:^16} | {str(bool(result)):^5} | TEST-{test_number:03} {r_string}", end='')
    print_logged_tag(result)
    test_number += 1

def test_assign(sub, role, expected_result):
    global test_number
    result = assign_role(EXAMPLE_ACM, sub, role)

    if result == expected_result:
        r_string = "PASSED"
    else:
        r_string = "FAILED"
        
    print(f"{sub:^10} | {role:^18} | {"ASSIGN":^16} | {str(bool(result)):^5} | TEST-{test_number:03} {r_string}", end='')
    print_logged_tag(result)
    test_number += 1

def test_is_owner(sub, obj, expected_result):
    global test_number
    result = is_owner(EXAMPLE_ACM, sub, obj)

    if result == expected_result:
        r_string = "PASSED"
    else:
        r_string = "FAILED"
        
    print(f"{sub:^10} | {obj:^18} | {"OWNER?":^16} | {str(bool(result)):^5} | TEST-{test_number:03} {r_string}")
    test_number += 1

def test_grant(sub, obj, act, expected_result):
    global test_number
    result = grant_permission(EXAMPLE_ACM, sub, obj, act)

    if result == expected_result:
        r_string = "PASSED"
    else:
        r_string = "FAILED"
    print(f"{sub:^10} | {obj:^18} | {"GRANT "+act:^16} | {str(bool(result)):^5} | TEST-{test_number:03} {r_string}", end='')
    print_logged_tag(result)
    test_number += 1
#
# Tests for RBAC portion
#

#Admin role test
test_authorization("JANE", "something.doc", "READ", True)
test_authorization("JANE", "something.doc", "WRITE", True)
test_authorization("JANE", "something.doc", "EXECUTE", True)
test_authorization("JANE", "something.doc", "SHARE", True)
#test 1-4

#Auditor role test
test_authorization("JOE", "something.doc", "READ", True)
test_authorization("JOE", "something.doc", "WRITE", False)
test_authorization("JOE", "something.doc", "EXECUTE", False)
test_authorization("JOE", "something.doc", "SHARE", False)
#test 5-8

#User role test
test_authorization("JOHN", "something.doc", "READ", False)
test_authorization("JOHN", "something.doc", "WRITE", False)
test_authorization("JOHN", "something.doc", "EXECUTE", False)
test_authorization("JOHN", "something.doc", "SHARE", False)
#test 8-12

#
# Tests for DAC portion
#

#test grant
grant_permission(EXAMPLE_ACM, "JOHN", "something.doc", "WRITE")
test_authorization("JOHN", "something.doc", "WRITE", True)
#test 13

#test revoke
revoke_permission(EXAMPLE_ACM, "JOHN", "something.doc", "WRITE")
test_authorization("JOHN", "something.doc", "WRITE", False)
#test 14

#test time-based permission
grant_permission(EXAMPLE_ACM, "JOHN", "something.doc", "WRITE", 3) #3-second permission
test_authorization("JOHN", "something.doc", "WRITE", True)
print("Testing Cooldown (4 seconds)...")
sleep(4) #4-second wait
test_authorization("JOHN", "something.doc", "WRITE", False)
#test 15-16

#test time-based early revoke
grant_permission(EXAMPLE_ACM, "JOHN", "something.doc", "WRITE", 10) #10-second permission
test_authorization("JOHN", "something.doc", "WRITE", True)
revoke_permission(EXAMPLE_ACM, "JOHN", "something.doc", "WRITE")
test_authorization("JOHN", "something.doc", "WRITE", False)
#test 17-18

#
# Role assignment tests
#
assign_role(EXAMPLE_ACM, "JANE", "AUDITOR")
test_authorization("JANE", "something.doc", "READ", True)
test_authorization("JANE", "something.doc", "WRITE", False)
test_authorization("JANE", "something.doc", "EXECUTE", False)
test_authorization("JANE", "something.doc", "SHARE", False)
#test 19-22

assign_role(EXAMPLE_ACM, "JOHN", "ADMIN")
test_authorization("JOHN", "something.doc", "READ", True)
test_authorization("JOHN", "something.doc", "WRITE", True)
test_authorization("JOHN", "something.doc", "EXECUTE", True)
test_authorization("JOHN", "something.doc", "SHARE", True)
#test 23-26

#
# Malformation tests (check logs for more details here)
#

#malformed check_authorization
test_authorization("place", "something.doc", "READ", False)
test_authorization("JOHN", "place", "READ", False)
test_authorization("JOHN", "something.doc", "place", False)
#test 27-29

#malformed assign
test_assign("place", "ADMIN", False)
test_assign("JANE", "place", False)
test_authorization("JANE", "something.doc", "READ", True)
test_authorization("JANE", "something.doc", "WRITE", False)
#test 30-33

#malformed grant
test_grant("place", "something.doc", "WRITE", False)
test_grant("JANE", "place", "WRITE", False)
test_grant("JANE", "something.doc", "place", False)
test_authorization("JANE", "something.doc", "READ", True)
test_authorization("JANE", "something.doc", "WRITE", False)
#test 34-38

#Redundant grant
test_grant("JANE", "something.doc", "READ", True)
test_grant("JANE", "something.doc", "READ", False)
#test 39-40

#Redundant role
test_assign("JANE", "AUDITOR", False)
#test 41

#
# Read-only test
#
assign_role(EXAMPLE_ACM, "JANE", "ADMIN")
test_authorization("JANE", "log.txt", "READ", True)
test_authorization("JANE", "log.txt", "WRITE", False)
test_authorization("JANE", "log.txt", "EXECUTE", False)
test_authorization("JANE", "log.txt", "SHARE", False)
test_authorization("JOE", "log.txt", "READ", True)
test_authorization("JOE", "log.txt", "WRITE", False)
#test 42-47

#
# is_owner test
# 
test_grant("JOE", "something.doc", "OWN", True)
test_is_owner("JOE", "something.doc", True)
revoke_permission(EXAMPLE_ACM, "JOE", "something.doc", "OWN")
test_is_owner("JOE", "something.doc", False)
#48-51

