package ae.veto.app;

import android.annotation.SuppressLint;
import android.content.Context;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.webkit.JavascriptInterface;
import android.webkit.ValueCallback;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;

/**
 * Runs the SAME Veto engine as the web app (engine/*.js + data/*.js, copied into the APK) in an
 * off-screen WebView. One rulebook for web and phone; works offline; the WebView may not load anything
 * from the network (every non-asset request is refused).
 */
final class Engine {
  interface Cb { void done(JSONObject r); }

  private static final String HOST = "appassets.androidplatform.net";
  private final Context ctx;
  private final Handler main = new Handler(Looper.getMainLooper());
  private final ArrayList<Runnable> pending = new ArrayList<>();
  private WebView web;
  private boolean ready;
  private int attempts;

  Engine(Context app) {
    ctx = app;
    main.post(new Runnable() { public void run() { create(); } });
  }

  boolean ready() { return ready; }

  /** Right after a phone boots (or while the WebView app updates) the WebView provider can be missing for a
   *  while. Never crash: retry with back-off; queued checks run as soon as the engine is up. */
  private void create() {
    try {
      build();
    } catch (Throwable t) {
      web = null;
      attempts++;
      long wait = Math.min(60000, 3000L * attempts);
      Log.w("Veto", "engine not available yet (" + t.getClass().getSimpleName() + "), retry in " + wait + " ms");
      main.postDelayed(new Runnable() { public void run() { create(); } }, wait);
    }
  }

  @SuppressLint({ "SetJavaScriptEnabled", "AddJavascriptInterface" })
  private void build() {
    web = new WebView(ctx);
    WebSettings s = web.getSettings();
    s.setJavaScriptEnabled(true);
    s.setAllowFileAccess(false);
    s.setAllowContentAccess(false);
    s.setDomStorageEnabled(false);
    s.setGeolocationEnabled(false);
    // engine errors (a module that fails to load, a thrown rule) go to logcat under the "Veto" tag
    web.setWebChromeClient(new android.webkit.WebChromeClient() {
      @Override public boolean onConsoleMessage(android.webkit.ConsoleMessage m) {
        if (m.messageLevel() == android.webkit.ConsoleMessage.MessageLevel.ERROR || m.messageLevel() == android.webkit.ConsoleMessage.MessageLevel.WARNING)
          Log.w("Veto", "engine console: " + m.message() + " (" + m.sourceId() + ":" + m.lineNumber() + ")");
        return true;
      }
    });
    web.addJavascriptInterface(new Object() {
      @JavascriptInterface public void ready() {
        main.post(new Runnable() { public void run() {
          ready = true;
          for (Runnable r : pending) r.run();
          pending.clear();
          Log.i("Veto", "engine ready");
        } });
      }
    }, "VetoNative");
    web.setWebViewClient(new WebViewClient() {
      @Override public WebResourceResponse shouldInterceptRequest(WebView v, WebResourceRequest req) {
        Uri u = req.getUrl();
        if (!HOST.equals(u.getHost()) || u.getPath() == null) { Log.w("Veto", "engine: blocked " + u); return refuse(403, "Blocked"); }
        String path = u.getPath().substring(1);
        try {
          InputStream in = ctx.getAssets().open(path);
          String mime = path.endsWith(".js") ? "text/javascript" : path.endsWith(".html") ? "text/html" : path.endsWith(".json") ? "application/json" : "application/octet-stream";
          return new WebResourceResponse(mime, "utf-8", in);
        } catch (IOException e) {
          if (!path.endsWith("favicon.ico")) Log.w("Veto", "engine: missing asset " + path + " (" + e + ")");
          return refuse(404, "Not found");
        }
      }
    });
    web.loadUrl("https://" + HOST + "/www/bridge.html");
  }

  private static WebResourceResponse refuse(int code, String why) {
    return new WebResourceResponse("text/plain", "utf-8", code, why, null, new ByteArrayInputStream(new byte[0]));
  }

  /** Evaluates a K.* expression and hands back its JSON result on the main thread. */
  void call(final String expr, final Cb cb) {
    final Runnable r = new Runnable() { public void run() {
      web.evaluateJavascript("(function(){try{return " + expr + ";}catch(e){return {error:String(e&&e.message||e)};}})()", new ValueCallback<String>() {
        public void onReceiveValue(String v) {
          JSONObject o = null;
          try { if (v != null && v.startsWith("{")) o = new JSONObject(v); } catch (Exception e) { Log.w("Veto", "bad engine reply", e); }
          if (o != null && o.has("error")) { Log.w("Veto", "engine error: " + o.optString("error")); }
          if (cb != null) cb.done(o);
        }
      });
    } };
    main.post(new Runnable() { public void run() {
      if (ready && web != null) r.run();
      else if (pending.size() < 50) pending.add(r);
    } });
  }

  void triage(String text, JSONObject ctxObj, Cb cb) { call("K.triage(" + JSONObject.quote(text) + "," + ctxObj + ")", cb); }
  void message(JSONObject input, boolean remember, Cb cb) { call("K.message(" + input + "," + remember + ")", cb); }
  void device(JSONObject ctxObj, Cb cb) { call("K.device(" + ctxObj + ")", cb); }
  void outgoing(String number, JSONObject opts, Cb cb) { call("K.outgoing(" + JSONObject.quote(number == null ? "" : number) + "," + opts + ")", cb); }
  void contacts(org.json.JSONArray list, Cb cb) { call("({list: K.contacts(" + list + ")})", cb); }
  void caller(String number, JSONObject opts, Cb cb) { call("K.caller(" + JSONObject.quote(number == null ? "" : number) + "," + opts + ")", cb); }
}
