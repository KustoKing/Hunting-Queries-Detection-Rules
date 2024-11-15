# Monitor Privileged Role Assignments

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1098.001 | Account Manipulation: Additional Cloud Roles | https://attack.mitre.org/techniques/T1098/001/ |

### Description

This hunting query identifies additions of users to privileged roles, specifically focusing on high-risk and administrative roles. Privileged roles grant elevated permissions, and unauthorized assignments can lead to privilege escalation or compromise of critical systems. The query detects both time-bound and permanent role assignments, allowing security teams to investigate potential misuse or abuse of administrative privileges. By monitoring defined roles using a comprehensive list of role GUIDs, this query ensures visibility into changes to sensitive role assignments across the organization. It also provides insight into the initiator of the action and the target user, helping to ensure accountability and traceability of privilege changes.

#### References

- [Entra ID Privileged Roles](https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference)

### Microsoft Sentinel Query

```kql
let PrivilegedRoles = datatable(RoleName:string, RoleGuid:string)
[
"Application Administrator", "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
"Application Developer", "cf1c38e5-3621-4004-a7cb-879624dced7c",
"Authentication Administrator", "c4e39bd9-1100-46d3-8c65-fb160da0071f",
"Authentication Extensibility Administrator", "25a516ed-2fa0-40ea-a2d0-12923a21473a",
"B2C IEF Keyset Administrator", "aaf43236-0c0d-4d5f-883a-6955382ac081",
"Cloud Application Administrator", "158c047a-c907-4556-b7ef-446551a6b5f7",
"Cloud Device Administrator", "7698a772-787b-4ac8-901f-60d6b08affd2",
"Conditional Access Administrator", "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
"Directory Writers", "9360feb5-f418-4baa-8175-e2a00bac4301",
"Domain Name Administrator", "8329153b-31d0-4727-b945-745eb3bc5f31",
"External Identity Provider Administrator", "be2f45a1-457d-42af-a067-6ec1fa63bc45",
"Global Administrator", "62e90394-69f5-4237-9190-012177145e10",
"Global Reader", "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
"Helpdesk Administrator", "729827e3-9c14-49f7-bb1b-9608f156bbb8",
"Hybrid Identity Administrator", "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2",
"Intune Administrator", "3a2c62db-5318-420d-8d74-23affee5d9d5",
"Lifecycle Workflows Administrator", "59d46f88-662b-457b-bceb-5c3809e5908f",
"Password Administrator", "966707d0-3269-4727-9be2-8c3a10f19b9d",
"Privileged Authentication Administrator", "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
"Privileged Role Administrator", "e8611ab8-c189-46e8-94e1-60213ab1f814",
"Security Administrator", "194ae4cb-b126-40b2-bd5b-6091b380977d",
"Security Operator", "5f2222b1-57c3-48ba-8ad5-d4759f1fde6f",
"Security Reader", "5d6b6bb7-de71-4623-b4af-96380a352509",
"User Administrator", "fe930be7-5e62-47db-91af-98c3a49a38b1"
];
AuditLogs
| where TimeGenerated > ago(730d)
| where OperationName has_all ("add","member to role","completed")
| where OperationName has_any('timebound','permanent')
| where TargetResources has_any(PrivilegedRoles | project RoleGuid)
| project TimeGenerated, AADTenantId,TargetResources, OperationName, InitiatedBy, AdditionalDetails
| extend
    TargetId = tostring(TargetResources[2].id),
    TargetType = tostring(TargetResources[2].type),
    TargetUser = tostring(TargetResources[2].userPrincipalName),
    TargetDisplayName = tostring(TargetResources[2].displayName),
    TargetRole = tostring(TargetResources[0].displayName),
    SourceId = tostring(InitiatedBy.user.id),
    SourceUser = tostring(InitiatedBy.user.userPrincipalName),
    SourceDisplayName = tostring(InitiatedBy.user.displayName)
| parse AdditionalDetails with * 'ipaddr","value":"' IPAdress '"' *
| project-away InitiatedBy, AdditionalDetails, TargetResources
```