# Security audit: Admin Management Xtended

**Audit target:** `admin-management-xtended` at commit `326149e894d889478e07498fd961e0d78978b555` (plugin version 2.5.2)

**Method:** Systematic static/data-flow review of every PHP entry point, AJAX registration, direct output path, database call, file/API operation, and bundled JavaScript sink. The request traces below assume a normal WordPress installation and identify the minimum WordPress capability needed at each entry point. No WordPress runtime or PHP interpreter is present in this checkout, so the audit did not include a live request test; the confirmed findings do not depend on an unobserved dynamic dispatch.

## Executive summary

There are no unauthenticated plugin entry points: every plugin AJAX hook is registered as `wp_ajax_*`, not `wp_ajax_nopriv_*`. The normal AJAX handlers call `check_ajax_referer()` and most also perform a capability check. However, several handlers trust client-supplied post-type information or use a broad object capability where WordPress's core operation requires a stronger capability.

### Confirmed exploitable findings

| ID | Type | Severity | Minimum privilege | Short description |
|---|---|---:|---|---|
| C-01 | Broken authorization / publish bypass | Medium | Authenticated user with `edit_post` on a post (a Contributor can satisfy this for their own post) | `ame_toggle_visibility` gates publishing on attacker-controlled `posttype`, then writes `post_status=publish` directly. |
| C-02 | Broken authorization / scheduling bypass | Medium | Authenticated user with `edit_post` but without the post type's publish capability | `ame_set_date` changes a post to `future` for a future date without checking `publish_posts`/`publish_pages`. |
| C-03 | Stored XSS | Medium | Authenticated user with `edit_post` on a post; victim must have edit access and click the tag-edit link | A tag name is HTML-escaped but then decoded into a JavaScript string in an inline event handler. |
| C-04 | Stored XSS | Medium | Authenticated user able to create/edit a post visible to an administrator; victim must click the plugin's title-edit link | A post title is inserted into a newly constructed `onclick` attribute without JavaScript/context encoding. |
| C-05 | Broken authorization / sticky-post control | Medium | Authenticated Author-level user with `edit_post` on an own published post | `stick_post()` is called after only an `edit_post` check; WordPress's normal save path requires stronger publish/edit-others capabilities. |
| C-06 | Broken authorization / arbitrary author assignment | Medium | Authenticated user with `edit_post` on a post | A user can set the post author to any numeric user ID without `edit_others_posts`/`edit_others_pages`. |
| C-07 | Broken object-level authorization | Low | Authenticated user with `edit_pages` but not necessarily `edit_others_pages` (custom page-editor role) | Page-order input can name arbitrary top-level page IDs; the handler never checks capability on each target page. |

No confirmed Critical or High severity issue was found. The Medium ratings reflect real integrity/XSS impact but require an authenticated low-privilege user and, for the XSS findings, victim interaction.

### Likely but unverified

* **L-01 – Exclude Pages object-level authorization:** the handler checks only `edit_pages` before passing an arbitrary `pageid` to the third-party `ep_set_option()` API. The third-party plugin is not part of this repository, so the final option-write behavior could not be inspected here. If `ep_set_option()` is the normal Exclude Pages setter (as its call contract indicates), this is the same cross-object authorization problem as C-07.
* **L-02 – Raw attachment description output:** `media-functions.php:93` emits `post_excerpt` without escaping. The plugin's own write path sanitizes the value with `sanitize_text_field()`, and WordPress normally KSES-filters attachment excerpts for users without `unfiltered_html`; the complete core/filter path is outside this checkout. A raw unsafe `post_excerpt` would execute, but a low-privilege way to put such a value there was not verified.

### Important non-findings

* All plugin `$wpdb` queries use `prepare()` and the table identifiers are fixed WordPress properties; no SQL injection path was confirmed.
* All state-changing plugin AJAX handlers have a nonce check. The link-category handler uses the wrong nonce action/field for the shipped JavaScript, so that feature is normally broken, but the check fails closed rather than creating a CSRF bypass.
* There are no REST routes, `wp_ajax_nopriv` handlers, remote HTTP clients, unsafe deserialization calls, upload/file-write/delete paths, or committed credentials/secrets.
* The PHP files lack conventional `ABSPATH` guards, but direct requests execute only definitions or terminate with a missing-WordPress-function/constant error; no direct-file-access exploit was found.

---

## Confirmed exploitable findings

### C-01 – Client-controlled post type bypasses the publish capability check

**Type:** Broken authorization / privilege bypass

**Severity:** Medium

**Entry point and sink:**

* Entry registration: `general-functions.php:668`, `wp_ajax_ame_toggle_visibility`.
* Handler: `general-functions.php:562-596`.
* Input and checks: `general-functions.php:564` (nonce), `566` (integer post ID), `568-570` (`current_user_can('edit_post', $postid)`), `572-574` (client-supplied `vis_status` and `posttype`).
* Dangerous state-changing sink: `general-functions.php:586` (prepared direct update of `post_status`), with the equivalent fallback at `general-functions.php:591`.

**End-to-end trace:**

1. A request reaches `/wp-admin/admin-ajax.php` with `action=ame_toggle_visibility`. Because the hook is `wp_ajax_*`, the caller must be logged in; there is no unauthenticated route.
2. `check_ajax_referer('ame_ajax_validation', 'security')` at line 564 verifies the nonce emitted by `wp_localize_script()` at `general-functions.php:985-991`.
3. `category_id` is converted with `intval()` at line 566. The handler then authorizes only `current_user_can('edit_post', $postid)` at lines 568-570.
4. `vis_status` and `posttype` are merely passed through `sanitize_text_field()` at lines 572-573. Sanitization does not make `posttype` authoritative; it remains fully attacker-controlled.
5. For `vis_status=publish`, the only publish check is `if ($posttype == 'post' && ! current_user_can('publish_posts'))` at lines 576-579. The handler never derives the real post type with `get_post_type()` and never checks the post type's capability object.
6. Any value other than the literal string `post` skips that check. The handler then passes the attacker-controlled status to a prepared query at line 586. The query is not SQL-injectable, but it performs the unauthorized state change.

**Minimum privilege:** an authenticated user who can edit the target post. A Contributor can edit their own draft but normally cannot publish it. The client-supplied type lets that user bypass the publish capability check. The same flaw also affects pages and custom post types because the handler does not use the target object's actual post type.

**Proof of concept:** with a Contributor's valid WordPress session and a nonce copied from the plugin's admin page:

```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Cookie: <contributor-session>
Content-Type: application/x-www-form-urlencoded

 action=ame_toggle_visibility&security=<ame_ajax_validation_nonce>&category_id=123&vis_status=publish&posttype=page
```

Use an own draft as post `123`; `posttype=page` is intentionally false even if post `123` is a normal post. The request passes the only capability check and executes the equivalent of:

```sql
UPDATE wp_posts SET post_status = 'publish' WHERE ID = 123
```

The same result can be obtained by sending an array/non-string for `posttype`, because the assignment at line 573 is conditional on `is_string()` and the later equality check then cannot succeed.

**Suggested fix:** derive the post type from the database and authorize the requested transition using its capability map. Do not accept `posttype` as an authorization input, and whitelist the state transitions.

```php
$post = get_post( $postid );
$ptype = $post ? get_post_type_object( $post->post_type ) : false;
if ( ! $ptype || ! current_user_can( $ptype->cap->edit_post, $postid ) ) {
    wp_die();
}

$status = isset( $_POST['vis_status'] )
    ? sanitize_key( wp_unslash( $_POST['vis_status'] ) )
    : '';
if ( ! in_array( $status, array( 'publish', 'draft' ), true ) ) {
    wp_die();
}
if ( 'publish' === $status && ! current_user_can( $ptype->cap->publish_posts ) ) {
    wp_die();
}

wp_update_post( array( 'ID' => $postid, 'post_status' => $status ) );
```

The exact allowed statuses should preserve the plugin's intended workflow, but every transition must use the real post type and its publish capability.

---

### C-02 – Future-date path schedules posts without a publish capability

**Type:** Broken authorization / privilege bypass

**Severity:** Medium

**Entry point and sink:**

* Entry registration: `general-functions.php:669`, `wp_ajax_ame_set_date`.
* Handler: `general-functions.php:524-554`.
* Checks and input: `general-functions.php:526` (nonce), `528` (post ID extraction), `530-532` (`edit_post`), `534` (`strtotime()` on `pickedDate`).
* Dangerous sink: `general-functions.php:541`, direct `post_status='future'` update.

**End-to-end trace:**

1. A logged-in user sends `action=ame_set_date` to `admin-ajax.php`. The handler verifies `ame_ajax_validation` at line 526 and converts the `datepicker<id>`-style ID with `intval(substr(...))` at line 528.
2. It authorizes only `current_user_can('edit_post', $postid)` at lines 530-532. No `publish_posts`/`publish_pages` check occurs before date or status changes.
3. `pickedDate` is parsed by `strtotime()` and normalized into a database date at line 534. This prevents SQL syntax injection, but it does not enforce a valid workflow transition.
4. When the requested date is in the future, the first branch at line 540 is taken. Lines 541-543 update `post_status` to `future` and fire plugin actions. The publish-capability check appears only in the later past-date branch at lines 545-548, and even there it depends on the client-controlled `posttype`.
5. Thus a user who can edit an own draft but cannot publish can schedule it. WordPress's normal post-save path treats `future` as a publish workflow and checks the post type's publish capability; this direct SQL path bypasses that policy.

**Minimum privilege:** authenticated user with `edit_post` but without the target type's publish capability; a Contributor's own draft is a concrete example.

**Proof of concept:** for own post `123`, `datepicker` is ten characters long, so the handler extracts `123` from `datepicker123`:

```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Cookie: <contributor-session>
Content-Type: application/x-www-form-urlencoded

 action=ame_set_date&security=<ame_ajax_validation_nonce>&category_id=datepicker123&pickedDate=2099-01-01%2012%3A00%3A00&posttype=post
```

The handler writes `post_date`, `post_date_gmt`, and then `post_status='future'` without requiring `publish_posts`. A WordPress cron run can subsequently publish the scheduled post.

**Suggested fix:** validate the date strictly, derive the post type from the post object, require `$ptype->cap->publish_posts` before changing an object to `future`, and perform the transition through a capability-checked WordPress update routine rather than an unconditional SQL status update. The `posttype` request parameter must not control authorization.

---

### C-03 – Tag names break out of the inline JavaScript handler (stored XSS)

**Type:** Stored cross-site scripting (XSS)

**Severity:** Medium

**Entry point and sinks:**

* Entry registration: `general-functions.php:680`, `wp_ajax_ame_ajax_save_tags`.
* Handler/input: `general-functions.php:158-169`; nonce at line 159, `edit_post` at lines 161-165, `sanitize_text_field()` at line 167, tag assignment at line 169.
* Stored/list-page sink: `post-functions.php:64-75`, especially line 75, which puts `$ame_post_tags_plain` in an inline `onclick` attribute.
* AJAX response sink: `general-functions.php:187` and `191-193`.
* Client-side HTML sink: `js/functions.js:41`, where the value is concatenated into an HTML input string.

**End-to-end trace:**

1. A logged-in user with `edit_post` sends `new_tags` to the registered AJAX action. The nonce and object capability checks are present and work, but neither is an XSS mitigation.
2. At line 167 the input is passed through `sanitize_text_field()`. That removes tags, line breaks, and invalid text, but it does not remove ordinary JavaScript punctuation such as `'`, `)`, `;`, or `/`.
3. `wp_set_post_tags()` at line 169 creates/assigns the term. The payload `');alert(document.domain);//` contains no comma, so it remains one tag name; WordPress term processing does not remove those punctuation characters.
4. When the post list is rendered, `post-functions.php:64-68` displays the name with `esc_html()`, but line 75 uses the separately assembled `$ame_post_tags_plain` as JavaScript source inside an HTML event handler. `esc_html()` is the wrong context: an entity such as `&#039;` is decoded by the browser while the event-handler source is constructed.
5. The generated handler for post `123` is effectively:

   ```html
   onclick="ame_ajax_form_tags(123, '');alert(document.domain);//');return false;"
   ```

   The attacker-controlled code runs when an editor/administrator clicks the tag-edit icon. The attacker need not have permission to edit the victim's post; the victim only needs `edit_post` on the post containing the tag, which an administrator normally has.
6. The same unsafe data flow is also present in the AJAX response at `general-functions.php:187` and in the client-side `value='...` construction at `js/functions.js:41`.

**Minimum privilege:** authenticated user with `edit_post` on an own post, such as a Contributor. Victim interaction with the plugin's tag-edit link is required.

**Proof of concept:** submit the following to the plugin's AJAX action using the attacker's own admin nonce:

```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Cookie: <contributor-session>
Content-Type: application/x-www-form-urlencoded

 action=ame_ajax_save_tags&security=<ame_ajax_validation_nonce>&postid=123&new_tags=');alert(document.domain);//
```

After an administrator opens `/wp-admin/edit.php`, the tag column for post `123` contains the malformed inline handler. Clicking its edit icon executes the alert; a real payload could make same-origin authenticated requests in the victim's WordPress session.

**Suggested fix:** do not put term data in inline event-handler source. Store it in an escaped `data-*` attribute and bind a handler with `jQuery.on()`, or use `wp_json_encode()` for the JavaScript argument and then escape the complete HTML attribute. Also change `ame_ajax_form_tags()` to construct a static input and call `.val(posttags)` instead of concatenating `posttags` into HTML.

For example, if an inline handler must temporarily remain:

```php
$onclick = 'ame_ajax_form_tags(' . absint( $postid ) . ', '
    . wp_json_encode( $ame_post_tags_plain )
    . ');return false;';
echo '<a ... onclick="' . esc_attr( $onclick ) . '">...</a>';
```

A DOM event binding is preferred because it removes both the PHP and JavaScript string-context problems.

---

### C-04 – Post titles are inserted into a new `onclick` attribute without JS encoding (stored XSS)

**Type:** Stored cross-site scripting (XSS)

**Severity:** Medium

**Entry point and sink:**

* Entry registration: `general-functions.php:670`, `wp_ajax_ame_save_title`.
* Input/storage path: `general-functions.php:499-515`; nonce at line 501, `edit_post` at lines 503-507, `sanitize_text_field()` at line 509, direct title update at line 511.
* Admin-page source: `general-functions.php:919-926` calls `ame_roll_through_title_rows()` on `edit.php`; the script is enqueued by `general-functions.php:975-984`.
* Dangerous JavaScript/HTML sink: `js/gui-modificators.js:21-24`, particularly line 24. The secondary input construction at `js/functions.js:270-276` is also unsafe once the malformed handler is invoked.

**End-to-end trace:**

1. An authenticated user with `edit_post` submits a title through `ame_save_title`. The handler checks the nonce at line 501 and the object capability at lines 503-507.
2. `sanitize_text_field()` at line 509 strips tags but retains a payload such as `x');alert(document.domain);//`. The value is written to `wp_posts.post_title` at line 511. The unescaped JavaScript returned at line 515 is an additional self-XSS sink, but the persistent cross-user path is the admin-list JavaScript below.
3. On a later posts-list request, WordPress's title link is normally HTML-escaped. `add_title_edit_links()` then calls `jQuery(this).html()` at line 22. That retrieves the title as text/HTML, including the apostrophe characters needed for the payload; the prior HTML escaping is not a JavaScript encoding boundary.
4. At line 24 the plugin concatenates `title` into an HTML string containing `onclick="ame_title_edit(..., 'TITLE', ...)"`. For the payload above, the resulting handler is effectively:

   ```html
   onclick="ame_title_edit(123, 'x');alert(document.domain);//', 'post');"
   ```

5. `ame_css_admin_header()` causes this code to run for the administrator's Posts page. When the administrator clicks the added title-edit pencil, the injected JavaScript executes in the WordPress admin origin.

**Minimum privilege:** authenticated user able to create/edit a post that an administrator can see in the Posts list. A Contributor's own draft title is sufficient. Victim interaction with the added title-edit icon is required.

**Proof of concept:** use the title-save action on an own post:

```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Cookie: <contributor-session>
Content-Type: application/x-www-form-urlencoded

 action=ame_save_title&security=<ame_ajax_validation_nonce>&category_id=123&new_title=x');alert(document.domain);//&posttype=post
```

Then have an administrator open `/wp-admin/edit.php` and click the plugin's title-edit icon next to post `123`. The alert demonstrates execution; a real payload could issue privileged same-origin requests.

**Suggested fix:** stop generating inline handlers from DOM HTML. Use `.text()` rather than `.html()` for a title and bind the click event with a closure:

```javascript
var title = jQuery(this).text();
var editLink = jQuery('<a>', { href: '#', 'class': 'ame-title-edit' });
editLink.on('click', function (event) {
    event.preventDefault();
    ame_title_edit(post_id, title, ameAjaxL10n.postType);
});
jQuery(this).after(editLink);
```

`ame_title_edit()` should likewise create the input element and set its value with `.val(title)`, not concatenate the title into an HTML string. The PHP title-save response at `general-functions.php:515` should use `wp_json_encode()`/`esc_js()` as appropriate even after the persistent sink is fixed.

---

### C-05 – Sticky-post operation lacks WordPress's stronger capability checks

**Type:** Broken authorization / cross-account site-integrity change

**Severity:** Medium

**Entry point and sink:**

* UI exposure: `post-functions.php:173-185` exposes the sticky action to every user who passes `current_user_can('edit_post', $ame_id)`.
* Entry registration: `general-functions.php:686`, `wp_ajax_ame_toggle_sticky`.
* Handler/checks: `general-functions.php:604-615`; nonce at line 605, ID conversion at line 607, only `edit_post` at lines 609-611.
* Dangerous sink: `general-functions.php:616` (`unstick_post`) or `general-functions.php:620` (`stick_post`), which changes the global sticky-post option.

**End-to-end trace:**

1. A logged-in user obtains the standard `ame_ajax_validation` nonce from the Posts list.
2. The endpoint accepts any post ID that passes `intval()` and only checks `current_user_can('edit_post', $postid)`.
3. It calls `stick_post()` or `unstick_post()` directly. There is no check for the target post type, sticky support, `edit_others_posts`, or the post type's `publish_posts` capability.
4. WordPress's normal post-save path only applies sticky state when the user has both the post type's `edit_others_posts` and `publish_posts` capabilities. The plugin bypasses those checks and directly changes the site's sticky-post list.

**Minimum privilege:** an Author can edit an own published post but normally lacks `edit_others_posts`; a Contributor can also reach the endpoint for an own editable post, although the visible front-page effect depends on the post being publishable.

**Proof of concept:**

```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Cookie: <author-session>
Content-Type: application/x-www-form-urlencoded

 action=ame_toggle_sticky&security=<ame_ajax_validation_nonce>&post_id=123
```

If post `123` is not sticky, the request calls `stick_post(123)` and makes it sticky without the normal stronger capability set.

**Suggested fix:** obtain the post type object, require its `edit_post` capability plus the same `edit_others_posts` and `publish_posts` capabilities used by core, verify that the post type supports sticky, and then call `stick_post()`/`unstick_post()`.

---

### C-06 – Arbitrary post author assignment is allowed with only `edit_post`

**Type:** Broken authorization / object-property authorization bypass

**Severity:** Medium

**Entry point and sink:**

* Entry registration: `general-functions.php:684`, `wp_ajax_ame_save_author`.
* Handler/checks: `general-functions.php:469-489`; nonce at line 471, ID conversion at line 473, only `edit_post` at lines 475-477, target ID conversion at line 479.
* Dangerous sink: `general-functions.php:489`, direct `post_author` update.
* The UI-producing handler at `general-functions.php:361-403` also checks only `edit_post`; the repeated check at the save endpoint is the security boundary, so the endpoint can be called directly even if the UI does not offer a particular user.

**End-to-end trace:**

1. A logged-in user sends `action=ame_save_author` with a valid nonce. The action is authenticated by `wp_ajax_*` and protected by `check_ajax_referer()` at line 471.
2. The target post ID is converted to an integer and `current_user_can('edit_post', $postid)` is checked. No capability is evaluated for changing ownership.
3. `newauthor` is converted to an integer, but the handler does not verify that the target user exists, belongs to the allowed author set, or that the caller has `edit_others_posts`/`edit_others_pages`.
4. The handler writes that arbitrary integer into `post_author` with a prepared query at line 489. The query is safe from SQL injection but not from unauthorized property modification.

WordPress's normal post-data translation rejects a different `post_author` when the caller lacks the relevant `edit_others_*` capability. This direct query omits that rule.

**Minimum privilege:** authenticated user with `edit_post` on the target object; a Contributor can use an own post.

**Proof of concept:** assuming user ID `1` is an administrator and post `123` is the attacker's own post:

```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Cookie: <contributor-session>
Content-Type: application/x-www-form-urlencoded

 action=ame_save_author&security=<ame_ajax_validation_nonce>&category_id=123&newauthor=1&typenumber=1
```

The post is reassigned to user 1 even though the Contributor lacks the capability WordPress requires to change the author. This is an integrity/ownership spoofing issue; it does not by itself grant the attacker the administrator's capabilities.

**Suggested fix:** use the target post type's capability map, require the relevant `edit_others_*` capability when the new author differs from the current author, validate the target with `get_user_by('id', ...)`, and use `wp_update_post()` after the explicit authorization check.

---

### C-07 – Page-order AJAX updates arbitrary top-level pages without per-object authorization

**Type:** Broken object-level authorization

**Severity:** Low

**Entry point and sink:**

* Entry registration: `general-functions.php:676`, `wp_ajax_ame_get_pageorder`.
* Checks/input: `general-functions.php:130-142`; nonce at line 132, global `edit_pages` check at lines 134-136, `sanitize_text_field()` at line 138, `parse_str()` at line 139.
* Dangerous sink: `general-functions.php:144`, direct `menu_order` update for each submitted ID.

**End-to-end trace:**

1. A logged-in user with `edit_pages` sends a valid nonce and a serialized page-order string.
2. The handler checks only the global primitive capability `edit_pages`; it does not call `current_user_can('edit_post', $value)` for each page ID.
3. `parse_str()` accepts arbitrary key/value pairs. For example, `x=456&y=789` becomes values `456` and `789`, which the handler iterates. This does not cause SQL injection because both values are used with `%d`, but it lets a direct caller name IDs independently of the UI's expected array shape.
4. For each value, the code checks only that the post has no parent, then updates `menu_order` where `post_type='page'`. There is no target ownership or `edit_others_pages` check.

**Minimum privilege:** a custom role with `edit_pages` but without `edit_others_pages` can edit/reorder its own pages yet alter the navigation order of another user's top-level page. A standard Editor already has the broader capability, so this finding primarily affects custom roles.

**Proof of concept:** for top-level pages 456 and 789:

```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Cookie: <custom-page-editor-session>
Content-Type: application/x-www-form-urlencoded

 action=ame_get_pageorder&security=<ame_ajax_validation_nonce>&pageordertable2=x=456&y=789
```

The first qualifying page is assigned `menu_order=0` and the second `menu_order=1` even if the caller cannot edit either target page. The exact effect is site navigation reordering, not arbitrary SQL execution.

**Suggested fix:** parse only the expected `pageordertable[]` structure, convert every ID with `absint()`, require `get_post_type($id)==='page'`, and either require `edit_others_pages` for the bulk reorder operation or check `current_user_can('edit_post', $id)` for every target before writing.

---

## Likely but unverified findings

### L-01 – Exclude Pages action is not object-authorized

**Type:** Likely broken object-level authorization

**Severity:** Low

**Trace:**

* Entry: `general-functions.php:685` registers `wp_ajax_ame_toggle_excludestatus`; handler starts at line 633.
* Nonce is checked at line 634 and `current_user_can('edit_pages')` at lines 636-638.
* The submitted page ID is only converted with `intval()` at line 644. There is no `get_post()` or `current_user_can('edit_post', $pageid)` check.
* With the Exclude Pages plugin active, line 646 reads its exclusion list, lines 647-653 adds/removes the arbitrary ID, and line 655 passes the resulting list to the external `ep_set_option()` setter.

**Why this is not marked confirmed:** `ep_set_option()` and `EP_OPTION_NAME` are supplied by the separately installed Exclude Pages plugin and are not present in this repository. The call clearly intends to persist the exclusion list, but the external setter's own authorization behavior could not be inspected as part of this checkout. If it is a simple option setter, the following request excludes another user's page from the site's navigation:

```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Cookie: <custom-page-editor-session>
Content-Type: application/x-www-form-urlencoded

 action=ame_toggle_excludestatus&security=<ame_ajax_validation_nonce>&pageid=456&statusid=1
```

**Suggested fix:** require the target page's appropriate edit capability (or a dedicated site-navigation capability) before calling the external setter, and reject IDs that are not pages.

---

### L-02 – Raw attachment excerpt is emitted into the media list

**Type:** Potential stored XSS

**Severity:** Low (unverified)

**Trace:**

* The media-list hook is registered at `media-functions.php:100-103`; `ame_custom_column_media_desc()` reads the attachment at lines 88-92.
* The sink is line 93, where `$q_media_desc->post_excerpt` is concatenated directly into HTML without `esc_html()` or `wp_kses_post()`.
* The plugin's own write entry is `general-functions.php:682` → `ame_ajax_save_mediadesc()` at line 72. It checks the nonce at line 74, checks `edit_post` at lines 78-80, sanitizes `new_mediadesc` with `sanitize_text_field()` at line 82, and writes it at line 83. That path strips markup before the value reaches the sink.
* A conditional payload such as `post_excerpt=<img src=x onerror=alert(document.domain)>` would execute when an authorized user opens `/wp-admin/upload.php`, but the ability for a low-privilege user to put that exact value into the attachment excerpt through WordPress core or another filter was not verified from this repository. Core's normal post/attachment save path generally KSES-filters values for users without `unfiltered_html`.

**Suggested fix:** use `esc_html($media_desc)` if the column is plain text, or explicitly use a tightly controlled `wp_kses()` allow-list if limited markup is required. Do not rely only on the separate AJAX write path because other WordPress code can populate `post_excerpt`.

---

## Not exploitable / false positives and coverage notes

### SQL injection

Every direct database call found in the PHP code is prepared. Examples include:

* `general-functions.php:83, 114, 118, 144, 348, 423, 456, 489, 511, 538-541, 583-586, 591`.
* `link-functions.php:143`.

IDs are converted with `intval()` in the object handlers, statuses are either fixed strings or bound as `%s`, and all user-controlled values are passed as prepare arguments. `$wpdb->posts` and `$wpdb->links` are fixed WordPress table properties, not request parameters. `parse_str()` in the page-order handler is a validation/authorization problem, not SQL injection: `%d` binding prevents SQL syntax injection.

### CSRF and AJAX authorization checks

The AJAX registrations are collected at `general-functions.php:668-686` and `link-functions.php:190-193`. The handlers call `check_ajax_referer()` before mutation, including the option-changing handlers:

* `ame_toggle_showinvisposts()` lines 275-284: nonce plus `edit_posts`.
* `ame_ajax_toggle_imageset()` lines 294-303: nonce plus `manage_options`.
* `ame_toggle_orderoptions()` lines 313-322: nonce plus `edit_pages`.
* Object handlers in `general-functions.php:72-665`: nonce plus an object/global capability as described above.
* Link handlers at `link-functions.php:130-143` and `155-169`: nonce plus `manage_links`.

The link-category handler calls `check_ajax_referer('ame_ajax_save_linkcategories')` without naming the `security` field at `link-functions.php:157`, while JavaScript sends the general nonce in `js/functions.js:123-126`. WordPress therefore looks for `_ajax_nonce`/`_wpnonce` rather than `security`, and the shipped UI request normally fails. A request with a valid nonce for the specific action is still required, so this is a fail-closed functionality defect, not a confirmed CSRF.

### XSS candidates that did not become independent findings

* Numeric IDs in the PHP HTML/JavaScript output are generally normalized with `esc_attr(intval(...))` after the 2.4.7 changes. They do not provide a practical injection path.
* Category names in `post-functions.php:121-123` and `general-functions.php:254-255` are passed through `sanitize_term_field(..., 'display')` and `esc_html()`. Category checklist output comes from WordPress's `wp_category_checklist()`.
* The tag-name issue is not mitigated by the `esc_html()` call because the value is later used as JavaScript source; it is therefore reported as C-03 rather than dismissed as a false positive.
* `general-functions.php:515` embeds `$new_title` into the response JavaScript without `wp_json_encode()`/`esc_js()`. A caller can make that response execute JavaScript in the caller's own browser, but the request requires that caller's nonce and the value is not used as a cross-user response. The same stored title becomes exploitable against another admin through `js/gui-modificators.js:24`, which is C-04.
* The response strings at `general-functions.php:589` and `594` include the sanitized request `posttype` without JavaScript encoding. This is likewise a nonce-protected, non-persistent response to the requesting user. It becomes a serious authorization problem in C-01 because the same field controls the publish-capability branch, but it is not an independent cross-user XSS finding.
* `link-functions.php:96-106` and `174-186` emit link-category display names with limited escaping. Link categories are processed through WordPress term display/KSES handling and the operation requires `manage_links`; no low-privilege active-script path was confirmed. Escaping these values at the final HTML/JavaScript context is still recommended.
* `general-functions.php:351` emits a post slug into an input. Post slugs are normalized by WordPress/`sanitize_title()` and the plugin also sanitizes new slugs at lines 443-448; no active markup path was found.

### Direct file access

`admin-management-xtended.php` and the included PHP files do not begin with the conventional `defined('ABSPATH') || exit;` guard. Direct requests are still not an exploit in this tree:

* `general-functions.php` only defines functions and conditionally registers hooks if `add_action` exists.
* `link-functions.php` similarly guards hook registration.
* `page-functions.php`, `post-functions.php`, and `media-functions.php` call WordPress functions directly and terminate with a missing-function error when loaded outside WordPress.
* `admin-management-xtended.php` attempts to use the undefined `ABSPATH`/WordPress APIs and terminates rather than serving source or performing a privileged operation.

Add guards as defense-in-depth, but this is not a confirmed information disclosure or code-execution issue.

### File operations, SSRF, deserialization, and secrets

The codebase contains no upload handler, `move_uploaded_file()`, file write/delete, path construction from request data, `unserialize()`, `wp_remote_get()`, cURL client, socket client, or REST route. The only file-related call is `file_exists()` in `ame_locale_exists()` at `general-functions.php:43`, using a plugin URL derived from the site/plugin installation rather than request data; it is not an arbitrary file read. No API keys, passwords, bearer tokens, or other hardcoded credentials were found.

### Bundled dependencies

There is no `composer.json`, `composer.lock`, `package.json`, or JavaScript lockfile. The plugin vendors very old browser libraries:

* `js/jquery-addons/jquery.datePicker.js` has an SVN `$Id` dated 2011-11-17.
* `js/jquery-addons/jquery.tablednd.js` documents version 0.5 from 2008.
* `js/jquery-addons/date.js` is a 2006 date prototype extension.

They run in the WordPress admin and the reviewed call sites pass site-controlled/localized strings rather than remote or front-end user input. I did not confirm a dependency-specific exploit from this code, but the libraries should be replaced or independently scanned against a maintained baseline. WordPress's core jQuery is enqueued rather than bundled by this plugin.
