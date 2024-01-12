# Summary

Brevo `mailin` plugin versions <= 3.1.72 with enabled double opt-in are vulnerable to an email flooding amplification attack.

*Code comments by authors marked with `LWM:`*

## Bugs

1. Plugin does not validate nonce for newsletter sign-up requests properly.
2. Plugin does not check whether addresses have already been sent a double-opt-in request

## Vulnerability

Bug 1 and 2 combine into one vulnerability:
**Plugin is vulnerable to email flooding attacks**

# Bug Reports

## 1: Plugin does not validate nonce for newsletter sign-up requests properly

**Affected versions**: <= 3.1.72

The nonce is checked for being non-empty, but not for correctness.

Attackers can simply submit the same, static non-empty string every time and don't have to do a request to retrieve a nonce first. Ever.

```php
    /* LWM: that's not how you check a token!  */
    if (empty($_POST['sib_security'])) {
        wp_send_json(
            array(
                'status' => 'sib_security',
                'msg' => 'Token not found.',
            )
        );
    }
```

Due to this, unused mailing lists can be subscribed to by blindly POSTing a crafted payload against any page of the site.

Lists are identified by incremental numeric IDs and can be subscribed to as long as the admin has

1. connected their brevo account
2. not enabled reCAPTCHA

Brevo has silently fixed this bug in plugin version 3.1.73 on 2024-01-12.

## 2: Plugin does not check whether addresses have already been sent a double-opt-in request

**Affected versions**: no fix issued as of 2024-01-12

If double opt-in is enabled, the Wordpress instance itself will send a confirmation email to the registrant before creating the subscription.

The single- and no opt-in code paths in `SIB_Manager->signup_process()` call `SIB_API_Manager::create_subscriber()` on POST, which includes a check for existing subscribers via the Brevo API.

The double opt-in code path does not do this before sending the opt-in email and also doesn't check for existing double opt-in requests of an email address.

```php
            if ($isDoubleOptin) {
                /*
                 * Double optin process
                 * 1. add record to db
                 * 2. send confirmation email with activate code
                 */


                $result = "success";
                // Send a double optin confirm email.

                /* LWM: useless if, value is never changed */
                if ('success' == $result) {
                    // Add a recode with activate code in db.
                    $activateCode = $this->create_activate_code($email, $info, $formID, $listID, $redirectUrlInEmail, $unlinkedLists);

                    /* LWM: create_subscriber() is not called, so user existence is not checked */
                    SIB_API_Manager::send_comfirm_email($email, 'double-optin', $templateID, $info, $activateCode);
                }
            } elseif ($isOptin) {
                $result = SIB_API_Manager::create_subscriber($email, $listID, $info, 'confirm', $unlinkedLists);
                if ('success' == $result) {
                    // Send a confirm email.
                    SIB_API_Manager::send_comfirm_email($email, 'confirm', $templateID, $info);
                }
            } else {
                $result = SIB_API_Manager::create_subscriber($email, $listID, $info, 'simple', $unlinkedLists);
            }
```

## Vulnerability: Plugin is vulnerable to email flooding attacks

The previously described Bugs 1 & 2 have the following implications:

1. An attacker can blindly (no previous GET needed) send POST requests to any frontend page of a Wordpress installation that meets the following criteria:

- Brevo plugin installed and Brevo account connected
- double opt-in enabled
- reCAPTCHA protection not enabled

2. This can be repeated infinitely for any email address\[es].

Having an essentially unchecked (no nonce validation, no nuffin') plugin that will happily send emails at the speed of the SMTP server make installations of this kind a perfect target for email flooding attacks that can stuff inboxes, get servers blacklisted and damage email reputation scores. 

An attacker can exploit this while posting requests to one server in parallel and doesn't have to wait for any responses to send more.

Brevo ships a default mailing list with a known id, meaning attackers don't need to custom tailor their payload to any site.
They can just POST a generic payload against any page on any Wordpress instance they encounter - the response will tell them whether they have hit a vulnerable site. 

This means even currently unused (no form accessible anywhere on the site) installations of the plugin that have double opt-in enabled, e.g. to meet GDPR guidelines, are a neat amplifier for email flooding attacks.  
While enabling Google reCAPTCHA would mitigate this, there is some considerations needed around using it, e.g. debate around GDPR-compliance of Google reCAPTCHA.

We have observed this attack in the wild, which lead to this investigation.

While Brevo has fixed Bug 1, nonce validation, on our requested response date (while not responding to us directly), we do not see a fix for Bug 2 in the updates 3.1.73 and 3.1.74, both released today (2024-01-12).

This means attackers now need to spend a single GET request once per site to get a valid nonce, before sending multiple POST requests to that site, each triggering a confirmation email, potentially all to the same recipient.
That's slightly better than before, but in our opinion still quite able to be abused, especially if you have multiple vulnerable Wordpress instances at hand.

Signed
- Sebastian Weiß [sebastian@lightweb-media.de](mailto:sebastian@lightweb-media.de)
- Jakob Berger [jakob@lightweb-media.de](mailto:jakob@lightweb-media.de)
