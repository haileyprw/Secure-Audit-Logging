# Secure-Audit-Logging

Part 1:
1.	Any event that involves any form of authentication is logged, any attempts to access something that the user does not have access to is logged. Any system errors or attempts to modify user rights are logged. 
2.	Only authorized users can read the log, administrators and those who are given access by administrators.
3.	The logs are written to a protected read only log file. 

Part 3: Apply Reference Monitor Criteria

| **Property**        | **How Our Design Satisfies the Property** |
|---------------------|-------------------------------------------|
| **Tamperproof**     | Our logs and access control mechanisms are protected from unauthorized modification. Logging is done through the `print_to_log()` function which writes to our log text file. Users cannot modify the `print_to_log()` behavior or the file itself through the DAC or RBAC system because `log.txt` is listed as `UNIVERSAL_READ_ONLY`, which denies all non-read actions (e.g., write or execute). We have also implemented an early exit condition in `check_authorization()` that checks if the file is read-only and the action is not read—ensuring DAC permissions can't override it. Our logging behavior is consistent regardless of user role (including admin). |
| **Always Invoked**  | Our access control mechanism is invoked for every access attempt. The `check_authorization()` function acts as a single bottleneck to verify access, and all operations are routed through it. This guarantees that no operation can be executed without proper authorization. Any unauthorized or invalid access attempts are immediately logged and denied. |
| **Simple (Analyzable)** | Our access control mechanism is simple and easy to understand, making it testable and analyzable. We use a modular structure with clear separation of concerns: role assignment, DAC rights, and authorization checks are handled by `assign_role()`, `grant_permission()`, and `check_authorization()` respectively. The codebase is well-documented to promote clarity and understanding of expected behavior.                             |

Part 4: Design Requirements


| **Requirement**        | **Design Function/Component** |
|------------------------|-------------------------------|
| **Logging authentication**| The `check_authorization()` function logs invalid subjects, objects, actions, and unauthorized attempts. The `assign_role()` and `grant_permission()` functions also log malformed roles, subjects, and redundant assignments.|
| **Only authorized users** | The `check_authorization()` function ensures that only users with the “AUDITOR” role can read the log, as specified in the RBAC structure.| 
| **Written to Read-Only File**| The `check_authorization()` function ensures that only users with the “AUDITOR” role can read the log, as specified in the RBAC structure.**|
|
