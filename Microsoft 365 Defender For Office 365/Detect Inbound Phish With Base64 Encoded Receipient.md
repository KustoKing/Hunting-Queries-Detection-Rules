# Detect Inbound Phish With Base64 Encoded Receipient

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566.002 | Spearphishing Link | https://attack.mitre.org/techniques/T1566/002/ |

### Description

This hunting query detects inbound E-mails which have not deliverd to quarantine, which contain URL's with base 64 encoded receipients E-mail address. 

#### References

### Microsoft 365 Defender

```
EmailEvents
| where EmailDirection == "Inbound"
    and not(DeliveryLocation  == "Quarantine")
| where AuthenticationDetails has_any("temperror","none","fail","softfail")
    and UrlCount > 0
| extend B64 = base64_encode_tostring(RecipientEmailAddress)
| extend AD = parse_json(AuthenticationDetails)
| join kind=inner EmailUrlInfo on NetworkMessageId
| where Url contains B64
| project-away *1
| join kind=leftouter UrlClickEvents on NetworkMessageId
```
