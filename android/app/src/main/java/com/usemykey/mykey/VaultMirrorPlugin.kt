// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.

package com.usemykey.mykey

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.database.Cursor
import android.net.Uri
import android.provider.DocumentsContract
import android.util.Base64
import androidx.activity.result.ActivityResult
import com.getcapacitor.JSObject
import com.getcapacitor.Plugin
import com.getcapacitor.PluginCall
import com.getcapacitor.PluginMethod
import com.getcapacitor.annotation.ActivityCallback
import com.getcapacitor.annotation.CapacitorPlugin

/**
 * The vault's home: a user-chosen folder (Storage Access
 * Framework) where the app keeps the canonical encrypted vault
 * file at MyKey/vault.mykey. The user picks the folder once;
 * Android persists the grant, so no storage permission is
 * declared and the app can touch nothing outside that grant.
 *
 * Only encrypted vault bytes cross this bridge — the same
 * ciphertext the app stores inside itself. Nothing here logs:
 * folder names and outcomes stay off logcat, like the rest of
 * the app's secret-handling surface.
 */
@CapacitorPlugin(name = "VaultMirror")
class VaultMirrorPlugin : Plugin() {

    private val prefs by lazy {
        context.getSharedPreferences("vaultmirror", Context.MODE_PRIVATE)
    }

    // ---------------------------------------------------------------
    // Folder grant
    // ---------------------------------------------------------------

    @PluginMethod
    fun pickFolder(call: PluginCall) {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).addFlags(
            Intent.FLAG_GRANT_READ_URI_PERMISSION or
                Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or
                Intent.FLAG_GRANT_PREFIX_URI_PERMISSION,
        )
        startActivityForResult(call, intent, "pickFolderResult")
    }

    @ActivityCallback
    private fun pickFolderResult(call: PluginCall, result: ActivityResult) {
        val uri = result.data?.data
        if (result.resultCode != Activity.RESULT_OK || uri == null) {
            val out = JSObject()
            out.put("cancelled", true)
            call.resolve(out)
            return
        }
        val flags = result.data?.flags?.and(
            Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
        ) ?: (Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
        try {
            context.contentResolver.takePersistableUriPermission(uri, flags)
        } catch (e: SecurityException) {
            call.reject("could not keep permission for that folder")
            return
        }
        prefs.edit().putString(KEY_TREE_URI, uri.toString()).apply()
        val out = JSObject()
        out.put("folderName", rootName(uri) ?: "your folder")
        call.resolve(out)
    }

    @PluginMethod
    fun forgetFolder(call: PluginCall) {
        treeUri()?.let { uri ->
            try {
                context.contentResolver.releasePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
                )
            } catch (e: SecurityException) {
                // The grant may already be gone; forgetting stands.
            }
        }
        prefs.edit().remove(KEY_TREE_URI).apply()
        call.resolve()
    }

    // ---------------------------------------------------------------
    // File operations (all inside the granted tree)
    // ---------------------------------------------------------------

    @PluginMethod
    fun folderInfo(call: PluginCall) {
        val out = JSObject()
        val uri = treeUri()
        if (uri == null || !hasGrant(uri)) {
            out.put("configured", false)
            out.put("folderName", null as String?)
            out.put("hasFile", false)
            out.put("modifiedAt", null as Long?)
            out.put("size", null as Long?)
            call.resolve(out)
            return
        }
        out.put("configured", true)
        out.put("folderName", rootName(uri) ?: "your folder")
        val file = findVaultFile(uri)
        out.put("hasFile", file != null)
        out.put("modifiedAt", file?.second)
        out.put("size", file?.third)
        call.resolve(out)
    }

    @PluginMethod
    fun readVaultFile(call: PluginCall) {
        val uri = treeUri() ?: run { call.reject("no home folder"); return }
        val file = findVaultFile(uri)
            ?: run { call.reject("no home file in that folder"); return }
        try {
            val bytes = context.contentResolver.openInputStream(file.first)
                ?.use { it.readBytes() }
                ?: run { call.reject("could not read the home file"); return }
            val out = JSObject()
            out.put("data", Base64.encodeToString(bytes, Base64.NO_WRAP))
            call.resolve(out)
        } catch (e: Exception) {
            call.reject("could not read the home file")
        }
    }

    @PluginMethod
    fun writeVaultFile(call: PluginCall) {
        writeFile(call, MirrorNames.FILE_NAME)
    }

    @PluginMethod
    fun writePreservedFile(call: PluginCall) {
        val name = MirrorNames.sanitizePreservedName(call.getString("name") ?: "")
        writeFile(call, name)
    }

    private fun writeFile(call: PluginCall, name: String) {
        val uri = treeUri() ?: run { call.reject("no home folder"); return }
        val data = call.getString("data")
            ?: run { call.reject("no data"); return }
        val bytes = try {
            Base64.decode(data, Base64.DEFAULT)
        } catch (e: IllegalArgumentException) {
            call.reject("bad data"); return
        }
        try {
            val dirId = ensureHomeDir(uri)
                ?: run { call.reject("could not open the home folder"); return }
            val existing = findChild(uri, dirId, name, isDir = false)
            val fileUri = existing?.first
                ?: DocumentsContract.createDocument(
                    context.contentResolver,
                    DocumentsContract.buildDocumentUriUsingTree(uri, dirId),
                    "application/octet-stream",
                    name,
                ) ?: run { call.reject("could not create the home file"); return }
            val stream = context.contentResolver.openOutputStream(fileUri, "wt")
                ?: run { call.reject("could not write the home file"); return }
            stream.use { it.write(bytes) }
            val out = JSObject()
            out.put("modifiedAt", queryMeta(fileUri)?.second ?: 0L)
            call.resolve(out)
        } catch (e: Exception) {
            call.reject("could not write the home file")
        }
    }

    // ---------------------------------------------------------------
    // DocumentsContract helpers
    // ---------------------------------------------------------------

    private fun treeUri(): Uri? =
        prefs.getString(KEY_TREE_URI, null)?.let { Uri.parse(it) }

    private fun hasGrant(uri: Uri): Boolean =
        context.contentResolver.persistedUriPermissions.any {
            it.uri == uri && it.isReadPermission && it.isWritePermission
        }

    private fun rootName(tree: Uri): String? {
        val docUri = DocumentsContract.buildDocumentUriUsingTree(
            tree, DocumentsContract.getTreeDocumentId(tree),
        )
        return queryMeta(docUri)?.first
    }

    /** (displayName, lastModified, size) for one document. */
    private fun queryMeta(docUri: Uri): Triple<String?, Long?, Long?>? {
        val projection = arrayOf(
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_LAST_MODIFIED,
            DocumentsContract.Document.COLUMN_SIZE,
        )
        return try {
            context.contentResolver.query(docUri, projection, null, null, null)?.use { c ->
                if (!c.moveToFirst()) return null
                Triple(strOrNull(c, 0), longOrNull(c, 1), longOrNull(c, 2))
            }
        } catch (e: Exception) {
            null
        }
    }

    /** (documentUri, lastModified, size) of a child by name. */
    private fun findChild(
        tree: Uri,
        parentDocId: String,
        name: String,
        isDir: Boolean,
    ): Triple<Uri, Long?, Long?>? {
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(tree, parentDocId)
        val projection = arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE,
            DocumentsContract.Document.COLUMN_LAST_MODIFIED,
            DocumentsContract.Document.COLUMN_SIZE,
        )
        return try {
            context.contentResolver.query(childrenUri, projection, null, null, null)?.use { c ->
                while (c.moveToNext()) {
                    val display = strOrNull(c, 1) ?: continue
                    val mime = strOrNull(c, 2)
                    val dir = mime == DocumentsContract.Document.MIME_TYPE_DIR
                    if (display == name && dir == isDir) {
                        val docId = strOrNull(c, 0) ?: continue
                        return Triple(
                            DocumentsContract.buildDocumentUriUsingTree(tree, docId),
                            longOrNull(c, 3),
                            longOrNull(c, 4),
                        )
                    }
                }
                null
            }
        } catch (e: Exception) {
            null
        }
    }

    /** The MyKey directory's document id; creates it on writes. */
    private fun ensureHomeDir(tree: Uri): String? {
        val rootId = DocumentsContract.getTreeDocumentId(tree)
        findChild(tree, rootId, MirrorNames.DIR_NAME, isDir = true)?.let { dir ->
            return DocumentsContract.getDocumentId(dir.first)
        }
        val created = DocumentsContract.createDocument(
            context.contentResolver,
            DocumentsContract.buildDocumentUriUsingTree(tree, rootId),
            DocumentsContract.Document.MIME_TYPE_DIR,
            MirrorNames.DIR_NAME,
        ) ?: return null
        return DocumentsContract.getDocumentId(created)
    }

    /** (documentUri, lastModified, size) of MyKey/vault.mykey. */
    private fun findVaultFile(tree: Uri): Triple<Uri, Long?, Long?>? {
        val rootId = DocumentsContract.getTreeDocumentId(tree)
        val dir = findChild(tree, rootId, MirrorNames.DIR_NAME, isDir = true) ?: return null
        val dirId = DocumentsContract.getDocumentId(dir.first)
        return findChild(tree, dirId, MirrorNames.FILE_NAME, isDir = false)
    }

    private fun strOrNull(c: Cursor, idx: Int): String? =
        if (c.isNull(idx)) null else c.getString(idx)

    private fun longOrNull(c: Cursor, idx: Int): Long? =
        if (c.isNull(idx)) null else c.getLong(idx)

    companion object {
        private const val KEY_TREE_URI = "treeUri"
    }
}
