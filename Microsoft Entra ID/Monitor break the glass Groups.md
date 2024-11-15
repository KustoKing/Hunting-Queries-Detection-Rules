# Monitor break the glass Groups

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1098.003 | Additional Cloud Roles | https://attack.mitre.org/techniques/T1098/003/ |

### Description

This hunting query monitors for additions and removals of users in groups designated for break-glass accounts, specifically by tracking defined group IDs. Break-glass accounts are high-privilege accounts intended for emergency access, typically restricted to critical administrators. Unauthorized changes to these groups could indicate privilege escalation or improper configuration, presenting a security risk if malicious actors add themselves or others to gain elevated permissions. The query tracks changes in membership over time, calculating the duration users remain in these sensitive groups and ensuring that break-glass privileges are granted only as needed and appropriately removed. By focusing on specific group IDs, this query provides targeted visibility into critical access controls.

#### References

### Microsoft Sentinel

```
let BreakGlass = dynamic(["GUID"]);
AuditLogs
| where TimeGenerated > ago(730d)
| where OperationName in("Add member to group", "Remove member from group")
| where TargetResources has_any (BreakGlass)
| project TimeGenerated, AADTenantId, TargetResources, OperationName, InitiatedBy
| extend
    TargetId    = tostring(TargetResources[0].id),
    TargetUser  = tostring(TargetResources[0].userPrincipalName),
    TargetGroup = trim('"', tostring(coalesce(TargetResources[0].modifiedProperties[0].oldValue, TargetResources[0].modifiedProperties[0].newValue))),
    SourceId    = tostring(InitiatedBy.user.id),
    SourceUser  = tostring(InitiatedBy.user.userPrincipalName),
    SourceIP    = tostring(InitiatedBy.user.ipAddress)
| project-away TargetResources, InitiatedBy
| where TargetGroup in (BreakGlass)
| sort by TargetId asc, TimeGenerated asc
| scan with_match_id=Funnel declare (AddedDate: datetime, RemovedDate: datetime) with (
    step Added: OperationName == "Add member to group" => AddedDate = TimeGenerated;
    step Removed: OperationName == "Remove member from group" and TargetId == Added.TargetId and TargetGroup == Added.TargetGroup => RemovedDate = TimeGenerated, AddedDate = Added.TimeGenerated;
)
| summarize arg_max(TimeGenerated, *) by Funnel, TargetId, TargetGroup
| extend HoursInGroup = case (isnotempty(RemovedDate), datetime_diff('hour', RemovedDate, AddedDate), datetime_diff('hour', now(), AddedDate))
```
