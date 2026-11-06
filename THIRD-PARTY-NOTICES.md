# Third-party notices

NDAS itself is licensed under the MIT License (see `LICENSE`). It uses or
bundles the following third-party components:

| Component | License | Notes |
| --- | --- | --- |
| .NET 8 / ASP.NET Core shared framework | MIT | Runtime and base class libraries |
| Microsoft.WindowsAppSDK | MIT | WinUI 3 application framework |
| Microsoft.Windows.SDK.BuildTools | MIT | Windows SDK build tooling |
| System.Management | MIT | WMI process monitoring |
| System.ServiceProcess.ServiceController | MIT | Windows service host |
| System.IO.Pipes.AccessControl | MIT | Named pipe ACLs |
| System.IO.FileSystem.AccessControl | MIT | File ACL blockade |
| System.Security.Cryptography.Pkcs | MIT | PKCS#7 policy inspection |

## Detection content

- `data/seed/yara/rules.yar` is derived from
  [Elastic protections-artifacts](https://github.com/elastic/protections-artifacts)
  and is redistributed under the **Elastic License 2.0** (ELv2). The license
  text is included at `data/seed/yara/LICENSE-elastic.txt`. These rules are
  data, not part of the NDAS source code, and remain under ELv2.
- IOC seed data (`data/seed/hashes.csv`, `domains.txt`, `ips-blocked.txt`,
  `special-paths.txt`) is sourced from
  [NDY-A/malware-egress-blocklist](https://github.com/NDY-A/malware-egress-blocklist)
  and released under CC0-1.0.

## Disclaimer

NDAS is a defensive security tool intended for systems you own or are
authorized to administer. It is an unsigned public beta; the installer and
binaries are not code-signed. Use at your own risk.
