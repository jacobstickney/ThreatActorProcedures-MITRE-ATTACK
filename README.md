# ThreatActorProcedures-MITRE-ATTACK

Threat actor procedures (the “P” in TTPs) are specific implementations of the tactics and techniques outlined in the [MITRE ATT&CK framework](https://attack.mitre.org/). They are the specific actions that threat actors take on a system or network after they have gained access. These actions often involve the use of command line activities.

These behaviors are specific procedural implementations of broader techniques that adversaries use to accomplish their goals. These techniques, such as System Network Configuration Discovery or Process Discovery, are linked to specific actions that illustrate how these techniques are implemented in real-world scenarios.

This is an ongoing collection of commands used by threat actors to perform various actions on a compromised system, accompanied by their respective MITRE ATT&CK technique reference numbers.


System Information Discovery [[T1082](https://attack.mitre.org/techniques/T1082/)]

```
systeminfo
net config workstation
tasklist /svc
ping -n 1 <remote_host>
net view
wmic product get name
wmic os caption
wmic process | find <security_product_process>
wmic volume list brief
wmic service brief
wmic product list brief
wmic baseboard list full
netsh interface firewall show all
netsh interface portproxy show all
netsh interface portproxy show v4tov4
netsh firewall show all
netsh portproxy show v4tov4
reg query hklm\software\
```
