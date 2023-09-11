# User elevated to User Access Administrator

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1098.003 | Additional Cloud Roles | https://attack.mitre.org/techniques/T1098/003/ |

### Description

This hunting query detects the elevation to User Access Administrator. This built-in role allows the user to assign themselves or others the Owner role to all subscriptions within a tenant.

#### References

### Microsoft Sentinel

```
arg("").authorizationresources
| where properties.roleDefinitionId == "/providers/Microsoft.Authorization/RoleDefinitions/18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
```
