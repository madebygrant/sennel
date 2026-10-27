# One-time codes

[Back to the README](../README.md)

Sennel keeps the two-factor codes for your accounts beside their passwords, so signing in is two key
presses: `p` for the password, `t` for the code. It handles the time-based codes (TOTP) that
authenticator apps show and KeePassXC stores.

## Adding a code

In the entry form, the one-time code box takes any of these:

- the `otpauth://` URL behind a site's QR code
- the secret a site prints for "can't scan it?", spaces and all (`JBSW Y3DP EHPK 3PXP`)
- a Google Authenticator "export accounts" link holding one account

The terminal app shows the code the box produces while you type, so you can check it against the
site before saving.

### From a QR code (desktop app)

1. Copy a screenshot of the site's QR code to the clipboard. On a Mac that is `⌘⇧⌃4`, then drag
   over the code.
2. In the entry form, press **Paste QR**, or paste straight into the code box. Dropping a saved
   image of the code onto the form works too.

The form fills in the code box and shows which account the QR names, such as
`for GitHub:ada@example.com`, with a live countdown. Then save as usual.

- Rust reads the image. The page never sees it.
- Sennel then clears the clipboard, because a picture of the QR code is the secret itself. A
  screenshot of some other kind of QR code stays where it was.
- A setup page often shows more than one code, such as an app store link. Sennel picks the
  one-time code.
- Codes drawn light on dark read as well as dark on light.
- Sennel takes time-based codes only. It refuses a counter-based (HOTP) code or a web link, and
  says why.
- It refuses images over 8192 pixels a side. Crop to the code.

## Using a code

| Where            | How                                                                 |
| ---------------- | ------------------------------------------------------------------- |
| Terminal app     | `t` copies the code. Entries with a code are marked `⊙`, and the detail view shows the digits and a countdown |
| Desktop app      | `t`, or click the one-time code row. The code's cells drain toward the next one and turn yellow in its last five seconds |
| Command line     | `sennel get github --otp` copies it, `--stdout` prints it ([more](get.md)) |

Sennel wipes a copied code after 30 seconds, like a password.

## Why the seed never leaves

The code changes every 30 seconds. The seed that makes it does not, and anyone holding it can make
codes forever. So Sennel copies the six digits and never the seed. Putting a permanent credential on
the clipboard to save typing six digits is a bad trade. The vault stores the seed protected, and the
desktop app doesn't even show the digits, only how long they have left.

[Security](security.md) has the rest of what is protected and how.
