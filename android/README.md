# Veto for Android: Kiki on your phone

The installable companion app. It runs the **same engine and rulebook** as the web app (`engine/`, `data/`
are copied into the APK) inside an off-screen WebView, and adds what only a phone knows: who is in your
contacts, how long you have chatted with someone, whether you are on a call, which app you just opened.

Kiki (the team's drawing, cut into 8 sprites by `tools/extract-pet.js`) is **hidden** and only appears when
something needs you: a warning, an unknown caller, a code arriving during a call, a risky chat you reopen.

## Build (no Gradle, no downloads)

Needs the Android SDK (build-tools + one platform) and a JDK 17.

```bash
npm run android          # = node tools/build-android.js  ->  android/build/veto.apk
```

The script calls `aapt2 → javac → d8 → zipalign → apksigner` directly and signs with a local debug key
(`android/debug.keystore`, created on first build; for the demo only).

## Install and switch on

```bash
adb install -r android/build/veto.apk
```

**On a real phone, install over USB, not by sending the file.** If you open `veto.apk` from Telegram, WhatsApp, a
browser or a file manager, Google Play Protect's fraud protection shows *"App blocked to protect your device"* and
offers only OK. It blocks apps installed that way when they ask for notification access, and reading message
notifications is exactly what Veto does. Installing from a computer over USB (adb) is the developer route and is not
blocked:

1. Phone: **Settings → About phone → Software information → tap "Build number" 7 times** (Developer options appear).
2. **Settings → Developer options → USB debugging: on.**
3. Samsung only: if **Settings → Security and privacy → Auto Blocker** is on, switch it off while you install
   (it blocks commands over the USB cable). Switch it back on afterwards.
4. Connect the USB cable, tap **Allow** on the phone's "Allow USB debugging?" prompt, then on the laptop:
   `adb devices` (the phone should be listed as `device`) and `adb install -r android/build/veto.apk`.
5. Open Veto and tap **Allow** on each row. Under **Apps Veto reads**, switch on only the chat apps you want checked;
   Veto never reads any other app.

For the hackathon this is the honest route. For real users the app would go through Google Play (a developer
account and a declaration for the notification-listener permission), which removes the block.

Open **Veto**. Each permission has its own row that says what it is for, in English and Arabic:

| Row | Android permission | Why |
|---|---|---|
| Show Kiki over other apps | Display over other apps | the pet + red warning card on top of WhatsApp / the dialer |
| Read new message notifications | Notification access | sender + text of NEW WhatsApp / SMS / Telegram notifications |
| Check unknown callers | Caller ID & spam app role | sees an unknown number before it rings (never blocks, never records) |
| Call state & contacts | Phone, Contacts | "on a call?" and the "Hi Mum, new number" check against your saved Mum |
| Notice your bank app during a call | Usage access | bank / AnyDesk opened DURING an unknown call, only checked then |
| Link Shield (optional) | Default browser role | every tapped link is checked first, then opened in your real browser |

Sideloaded apps on Android 13+ may show "Restricted setting" for notification access: open
*Settings → Apps → Veto → ⋮ → Allow restricted settings* first.

For a quick demo on an emulator / test phone, the same switches from the command line:

```bash
adb shell appops set ae.veto.app SYSTEM_ALERT_WINDOW allow
adb shell cmd notification allow_listener ae.veto.app/ae.veto.app.ChatListener
adb shell pm grant ae.veto.app android.permission.READ_PHONE_STATE
adb shell pm grant ae.veto.app android.permission.READ_CONTACTS
adb shell pm grant ae.veto.app android.permission.POST_NOTIFICATIONS
adb shell appops set ae.veto.app GET_USAGE_STATS allow
adb shell cmd role add-role-holder android.app.role.CALL_SCREENING ae.veto.app
```

## What it does

* **Chats (WhatsApp, SMS, Telegram, Signal, BOTIM …)**, `ChatListener` reads each new notification.
  The trust ledger (counts + first-seen date per sender, hashed, never text) decides attention:
  trusted family chat → *not analysed, Kiki stays hidden*; stranger / foreign / first message → full check.
  The engine compares what the message **claims** with what the phone **knows**:
  "Dubai Police" from a +92 WhatsApp, "Hi Mum" from a number that isn't Mum's, a first message that already
  asks for money. A scam opens a red card that says why ("Dubai Police never asks you to share your card's
  CVV", quoted from the rulebook), with **Report** (Aman 800 2626, SMS 2828, eCrime, copy evidence),
  **Warn family**, **I know them**.
* **Calls**, `CallGuard` (CallScreeningService) gets an unknown number before it rings: country, one-ring
  ranges (+674 …), hidden numbers, official bank numbers (with "caller ID can be faked"), numbers you reported,
  and, if you switch on online checks, IPQualityScore reputation (fraud score, recently reported, VoIP).
  During the call Kiki watches the **footprints** of a coached scam (no audio needed): a bank code arriving,
  your banking app or AnyDesk opening, a new app being installed → **sharp beep in the earpiece**, vibration,
  "hang up now".
* **Links**, `LinkShieldActivity` (default link opener or "Share → Veto") checks a link on the phone and,
  with online checks on, asks the Veto X-ray server what the page **wants** and where it **sends** your data.

## Privacy

Everything runs on the phone. Trusted chats are never read. No call audio (Android forbids it; Veto
doesn't need it). Veto never taps, types, replies or sends for you, every action opens the dialer, SMS
or share sheet. Online checks are off by default and then send only a link or a phone number.

## Limits (honest)

* Reads what the notification shows: if WhatsApp previews are hidden, there is nothing to read.
* WhatsApp **calls** (not phone calls) are not seen by the call-screening role; the "code during a call"
  check needs a phone call.
* Bank-app detection matches app names ("bank", "ADCB", "FAB" …), tune the list before production.
* The debug key and `usesCleartextTraffic` (for a laptop X-ray server on Wi-Fi) are demo settings.
