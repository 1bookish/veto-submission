package ae.veto.app;

import android.content.Context;
import android.media.AudioAttributes;
import android.media.AudioManager;
import android.media.ToneGenerator;
import android.os.Handler;
import android.os.Looper;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.speech.tts.TextToSpeech;

import java.util.Locale;

/**
 * The sharp beep. During a call it plays on the CALL stream, so you hear it in your ear while the
 * scammer is talking (the other side does not hear it); otherwise on the alarm stream. Plus a
 * vibration pattern, and an optional spoken "hang up now".
 */
final class Alarm {
  private Alarm() {}

  private static TextToSpeech tts;
  private static boolean ttsReady;

  static void alert(Context c, boolean inCall, boolean speak) {
    beep(c, inCall);
    if (speak && inCall) say(c, Text.t(c, "Veto warning. Hang up now.", "تحذير من فيتو. أنهِ المكالمة الآن."), true);
  }

  static void beep(Context c, boolean inCall) {
    try {
      final ToneGenerator tg = new ToneGenerator(inCall ? AudioManager.STREAM_VOICE_CALL : AudioManager.STREAM_ALARM, 100);
      tg.startTone(ToneGenerator.TONE_CDMA_ALERT_CALL_GUARD, 1500);
      new Handler(Looper.getMainLooper()).postDelayed(new Runnable() { public void run() { tg.release(); } }, 1900);
    } catch (RuntimeException ignored) { /* audio busy */ }
    vibrate(c);
  }

  static void vibrate(Context c) {
    try {
      Vibrator v = (Vibrator) c.getSystemService(Context.VIBRATOR_SERVICE);
      if (v != null && v.hasVibrator()) v.vibrate(VibrationEffect.createWaveform(new long[] { 0, 350, 150, 350, 150, 650 }, -1));
    } catch (RuntimeException ignored) { /* no vibrator */ }
  }

  static void say(final Context c, final String text, final boolean inCall) {
    if (tts == null) {
      tts = new TextToSpeech(c.getApplicationContext(), new TextToSpeech.OnInitListener() {
        public void onInit(int status) { ttsReady = status == TextToSpeech.SUCCESS; if (ttsReady) say(c, text, inCall); }
      });
      return;
    }
    if (!ttsReady) return;
    int ok = tts.setLanguage(Text.ar(c) ? new Locale("ar") : Locale.UK);
    if (ok < 0) tts.setLanguage(Locale.UK);
    tts.setAudioAttributes(new AudioAttributes.Builder()
        .setUsage(inCall ? AudioAttributes.USAGE_VOICE_COMMUNICATION : AudioAttributes.USAGE_ASSISTANCE_SONIFICATION)
        .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH).build());
    tts.speak(text, TextToSpeech.QUEUE_FLUSH, null, "veto");
  }
}
