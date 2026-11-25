# Veto.ai browser extension

Checks every website you open, and the messages you read on WhatsApp Web, Google Messages, Telegram Web, Gmail and
Outlook, on your own computer. It is the same engine as the Veto server and the phone app: the URL Judge for websites
and links, and the message check (rulebook, URL Judge on every link, on-device text model) for messages.

## Install (Chrome, Edge, Brave, Opera)

```
npm run build:extension
```

Then open `chrome://extensions` (or `edge://extensions`), switch on **Developer mode**, click **Load unpacked** and pick
the `build/extension` folder. `build/veto-extension.zip` is the same folder, packed, to share.

## What it does

| Where | What you see |
|---|---|
| A scam website | A full-screen warning with the reasons, in English or Arabic, and the police numbers. Buttons: leave, continue this time, or trust the site. A red **!** on the toolbar icon. |
| A suspicious website | A bar at the top with the main reason. An orange **?** on the icon. |
| An official UAE institution's site | A green **✓** on the icon. |
| WhatsApp Web, Google Messages, Telegram, Gmail, Outlook | A small label under each risky message ("Scam", "Be careful", "One-time code: never share it"). |
| Right-click on selected text or a link | "Check with Veto.ai": a notification with the verdict. |
| The toolbar popup | The verdict for the open website, and a box to paste any message or link. |

## Privacy

Everything runs in the browser. Nothing is sent anywhere unless you switch it on in Settings:

- **Online link checks** go to your own Veto server (`npm start`, default `http://localhost:8787`), only for links that
  are not clearly safe. The server follows redirects and short links, reads what the page asks for, and checks the
  domain's age.
- **AI second opinion**: for messages the rules cannot read (other languages; the AI translates them) or when the rules
  and the text model disagree. Card numbers, codes, phone numbers and e-mail addresses are removed before the text is
  sent. The Veto server's AI (Claude) is used first; otherwise your own Groq key, stored only in this browser. The AI
  can add a warning, never remove one.

## Test

```
npm run test:extension
```

Loads the built extension into Edge or Chrome without a window and checks the warning, the badges, the message labels
and the popup. Every site in the test is served by the test itself; no real scam site is contacted. Set
`VETO_TEST_GROQ_KEY` in the environment to also test the AI step (an Urdu message is translated and flagged).
