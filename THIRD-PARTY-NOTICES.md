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

## Built-in sandbox (installed under `Program Files\NDAS\Sandbox`)

| Component | License | Notes |
| --- | --- | --- |
| Speakeasy (Mandiant) | MIT | User-mode PE emulator used for dynamic behavior analysis |
| Python (embeddable) | PSF License | Runtime that hosts Speakeasy |
| Unicorn Engine | GPL-2.0 | CPU emulation core; distributed as the PyPI win_amd64 wheel, source at https://github.com/unicorn-engine/unicorn |
| Capstone Engine | BSD 3-Clause | Disassembly engine |
| pefile | MIT | PE parsing |
| pycryptodome | BSD 2-Clause | Cryptographic primitives |
| lznt1 | MIT | LZNT1 decompression |
| jsonschema | MIT | Report validation |

Full license texts are copied into `Sandbox\LICENSES` by
`installer/prepare-sandbox.ps1`. The sandbox emulator never executes the
sample natively; it runs inside a job object with a low-integrity token when
available and an outbound firewall block for its Python executable.

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
