# Android interoperability research runner

This repository contains a reproducible GitHub Actions environment for authorized
interoperability research on an Android application. It starts a rooted Android
KVM emulator and captures runtime files needed to build a Home Assistant integration.

No account credentials, HAR files, cookies, access tokens, private keys, APK files,
plaintext runtime files, or decrypted application code are stored in this repository
or uploaded as workflow artifacts.

## Artifact encryption

All runtime output and diagnostics are packed inside the runner and encrypted as CMS
`AuthEnvelopedData` using RSA-4096 and AES-256-GCM. Only the public recipient
certificate is committed. The corresponding private key remains offline and is
required to decrypt an artifact.

Recipient certificate SHA-256 fingerprint:

```text
68:FB:70:88:73:4F:10:E3:F2:95:5A:1A:90:14:E7:D1:B0:12:26:91:9E:2B:2D:7D:75:9D:DD:46:F9:C8:34:9B
```

Artifacts are retained for one day. The official APK is downloaded by the runner,
verified against a pinned SHA-256 digest, and excluded from the artifact.

## Unpacking workflow notes

`unpack-apk.yml` repackages the vendor x86 shell and redirects anti-tamper
JUMP_SLOT imports (`kill` / `exit` / `abort` / `ptrace` /
`android_set_abort_message`) to `getpid`. DarkDex waits for a stable PID,
skips `/system`/`/apex` maps, warms ~5s for decrypt, and only treats carves
as success when business markers appear (not boot-image framework DEX).
`wrap.<package>` is intentionally disabled: it triggers WrapperInit and
pollutes the process with framework DEX. All of this is CI-only research
tooling.
