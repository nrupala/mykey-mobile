package com.usemykey.mykey;

import android.os.Bundle;

import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        registerPlugin(SensitiveClipboardPlugin.class);
        super.onCreate(savedInstanceState);
    }
}
