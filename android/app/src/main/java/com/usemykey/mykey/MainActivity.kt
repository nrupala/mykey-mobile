// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.

package com.usemykey.mykey

import android.os.Bundle
import com.getcapacitor.BridgeActivity
import com.usemykey.mykey.passkey.PasskeyProviderPlugin

class MainActivity : BridgeActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        registerPlugin(SensitiveClipboardPlugin::class.java)
        registerPlugin(PasskeyProviderPlugin::class.java)
        super.onCreate(savedInstanceState)
    }
}
