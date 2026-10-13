package com.usemykey.mykey;

import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Build;
import android.os.PersistableBundle;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

/**
 * Clipboard access that treats copied MyKey secrets as secrets.
 *
 * Writes mark the clip sensitive via ClipboardManager's
 * EXTRA_IS_SENSITIVE (Android 13+), so the system clipboard preview
 * and keyboard clipboard history do not display or retain the value
 * as ordinary text. Reads return the current primary clip text so
 * the web layer can apply its "clear only what we put there" rule.
 */
@CapacitorPlugin(name = "SensitiveClipboard")
public class SensitiveClipboardPlugin extends Plugin {

    private ClipboardManager clipboard() {
        return (ClipboardManager) getContext().getSystemService(Context.CLIPBOARD_SERVICE);
    }

    @PluginMethod
    public void write(PluginCall call) {
        String value = call.getString("value", "");
        ClipboardManager cm = clipboard();
        if (cm == null) {
            call.reject("Clipboard unavailable");
            return;
        }
        ClipDescription description = new ClipDescription(
            "MyKey secret",
            new String[] { ClipDescription.MIMETYPE_TEXT_PLAIN }
        );
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            PersistableBundle extras = new PersistableBundle();
            extras.putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true);
            description.setExtras(extras);
        }
        cm.setPrimaryClip(new ClipData(description, new ClipData.Item(value)));
        call.resolve();
    }

    @PluginMethod
    public void read(PluginCall call) {
        JSObject result = new JSObject();
        String text = "";
        ClipboardManager cm = clipboard();
        if (cm != null && cm.hasPrimaryClip()) {
            ClipData clip = cm.getPrimaryClip();
            if (clip != null && clip.getItemCount() > 0) {
                CharSequence item = clip.getItemAt(0).getText();
                if (item != null) {
                    text = item.toString();
                }
            }
        }
        result.put("value", text);
        call.resolve(result);
    }

    @PluginMethod
    public void clear(PluginCall call) {
        ClipboardManager cm = clipboard();
        if (cm != null) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                cm.clearPrimaryClip();
            } else {
                cm.setPrimaryClip(ClipData.newPlainText("", ""));
            }
        }
        call.resolve();
    }
}
