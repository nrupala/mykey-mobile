// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.

package com.usemykey.mykey

import android.os.Bundle
import android.view.WindowManager
import com.getcapacitor.BridgeActivity
import com.usemykey.mykey.passkey.PasskeyProviderPlugin

class MainActivity : BridgeActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        registerPlugin(SensitiveClipboardPlugin::class.java)
        registerPlugin(PasskeyProviderPlugin::class.java)
        registerPlugin(MyKeyAutofillPlugin::class.java)
        super.onCreate(savedInstanceState)
        // The whole app is one WebView hosting the unlock and entry
        // screens: FLAG_SECURE keeps secrets out of screenshots and
        // the recents thumbnail.
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }
}
