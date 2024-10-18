package com.machiav3lli.fdroid.content

import android.content.ContentValues
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.Build
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import android.system.Os
import androidx.core.content.FileProvider
import androidx.documentfile.provider.DocumentFile
import com.anggrayudi.storage.file.getAbsolutePath
import com.machiav3lli.fdroid.R
import com.machiav3lli.fdroid.utility.extension.android.Android
import com.machiav3lli.fdroid.utility.getDownloadFolder
import com.machiav3lli.fdroid.utility.isDownloadExternal
import java.io.File
import java.util.UUID
import kotlin.concurrent.thread

object Cache {
    private fun ensureCacheDir(context: Context, name: String): File {
        return File(
            context.cacheDir,
            name
        ).apply { isDirectory || mkdirs() || throw RuntimeException() }
    }

    private fun ensureExtCacheDir(context: Context, name: String): File {
        return File(
            context.externalCacheDir,
            name
        ).apply { isDirectory || mkdirs() || return ensureCacheDir(context, name) }
    }

    private fun applyOrMode(file: File, mode: Int) {
        val oldMode = Os.stat(file.path).st_mode and 0b111111111111
        val newMode = oldMode or mode
        if (newMode != oldMode) {
            Os.chmod(file.path, newMode)
        }
    }

    fun getImagesDir(context: Context): File {
        return ensureCacheDir(context, "images")
    }

    fun getPartialReleaseFile(context: Context, cacheFileName: String): File {
        return File(ensureExtCacheDir(context, "partial"), cacheFileName)
    }

    fun getReleaseFile(context: Context, cacheFileName: String): File {
        return File(ensureExtCacheDir(context, "releases"), cacheFileName)
    }

    fun File.getReleaseFileUri(context: Context): Uri {
        val authority = context.applicationContext.packageName + ".provider.files"
        return FileProvider.getUriForFile(context, authority, this)
    }

    fun Context.getPackageArchiveInfo(file: File): PackageInfo? =
        if (Android.sdk(Build.VERSION_CODES.TIRAMISU))
            packageManager.getPackageArchiveInfo(file.absolutePath, PackageManager.PackageInfoFlags.of(0))
        else packageManager.getPackageArchiveInfo(file.absolutePath, 0)

    fun getTemporaryFile(context: Context): File {
        return File(ensureCacheDir(context, "temporary"), UUID.randomUUID().toString())
    }

    fun cleanup(context: Context) {
        thread {
            cleanup(
                context,
                context.cacheDir,
                Pair("images", Preferences[Preferences.Key.ImagesCacheRetention] * 24),
                Pair("temporary", 1),
                // in case the external cache was unavailable (maybe only temporary)
                Pair("partial", 24),
                Pair("releases", Preferences[Preferences.Key.ReleasesCacheRetention] * 24),
            )
            cleanup(
                context,
                context.externalCacheDir,
                Pair("partial", 24),
                Pair("releases", Preferences[Preferences.Key.ReleasesCacheRetention] * 24),
            )
        }
    }

    private fun cleanup(context: Context, dir: File?, vararg dirHours: Pair<String, Int>) {
        val knownNames = dirHours.map { it.first }.toSet()
        val files = dir?.listFiles().orEmpty()
        files.filter { it.name !in knownNames }.forEach {
            if (it.isDirectory) {
                cleanupDir(it, 0)
                it.delete()
            } else {
                it.delete()
            }
        }
        dirHours.forEach { (name, hours) ->
            if (hours > 0) {
                val file = File(dir, name)
                if (file.exists()) {
                    if (file.isDirectory) {
                        cleanupDir(file, hours)
                    } else {
                        file.delete()
                    }
                }
                if (name == "releases" && isDownloadExternal)
                    cleanupDir(context, context.getDownloadFolder(), hours)
            }
        }
    }

    private fun cleanupDir(dir: File, hours: Int) {
        dir.listFiles()?.forEach {
            val older = hours <= 0 || run {
                val olderThan = System.currentTimeMillis() / 1000L - hours * 60 * 60
                try {
                    val stat = Os.lstat(it.path)
                    stat.st_atime < olderThan
                } catch (e: Exception) {
                    false
                }
            }
            if (older) {
                if (it.isDirectory) {
                    cleanupDir(it, hours)
                    if (it.isDirectory) {
                        it.delete()
                    }
                } else {
                    it.delete()
                }
            }
        }
    }

    private fun cleanupDir(context: Context, dir: DocumentFile?, hours: Int) {
        dir?.listFiles()?.forEach {
            val older = hours <= 0 || run {
                val olderThan = System.currentTimeMillis() / 1000L - hours * 60 * 60
                try {
                    val stat = Os.lstat(it.getAbsolutePath(context))
                    stat.st_atime < olderThan
                } catch (e: Exception) {
                    false
                }
            }
            if (older) {
                if (it.isDirectory) {
                    cleanupDir(context, it, hours)
                    if (it.isDirectory) {
                        it.delete()
                    }
                } else {
                    it.delete()
                }
            }
        }
    }

    class Provider : FileProvider(R.xml.cache_provider) {
        companion object {
            private val defaultColumns = arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)
        }

        private fun getFileAndTypeForUri(uri: Uri): Pair<File, String> {
            return when (uri.pathSegments?.firstOrNull()) {
                "releases" -> Pair(
                    File(context!!.cacheDir, uri.encodedPath!!),
                    "application/vnd.android.package-archive"
                )

                else       -> throw SecurityException()
            }
        }

        override fun onCreate(): Boolean = true

        override fun query(
            uri: Uri, projection: Array<String>?,
            selection: String?, selectionArgs: Array<out String>?, sortOrder: String?,
        ): Cursor {
            val file = getFileAndTypeForUri(uri).first
            val columns = (projection ?: defaultColumns).mapNotNull {
                when (it) {
                    OpenableColumns.DISPLAY_NAME -> Pair(it, file.name)
                    OpenableColumns.SIZE         -> Pair(it, file.length())
                    else                         -> null
                }
            }.unzip()
            return MatrixCursor(columns.first.toTypedArray()).apply { addRow(columns.second.toTypedArray()) }
        }

        override fun getType(uri: Uri): String = getFileAndTypeForUri(uri).second

        private val unsupported: Nothing
            get() = throw UnsupportedOperationException()

        override fun insert(uri: Uri, contentValues: ContentValues?): Uri = unsupported
        override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int =
            unsupported

        override fun update(
            uri: Uri, contentValues: ContentValues?,
            selection: String?, selectionArgs: Array<out String>?,
        ): Int = unsupported

        override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor? {
            val openMode = when (mode) {
                "r"       -> ParcelFileDescriptor.MODE_READ_ONLY
                "w", "wt" -> ParcelFileDescriptor.MODE_WRITE_ONLY or ParcelFileDescriptor.MODE_CREATE or
                        ParcelFileDescriptor.MODE_TRUNCATE

                "wa"      -> ParcelFileDescriptor.MODE_WRITE_ONLY or ParcelFileDescriptor.MODE_CREATE or
                        ParcelFileDescriptor.MODE_APPEND

                "rw"      -> ParcelFileDescriptor.MODE_READ_WRITE or ParcelFileDescriptor.MODE_CREATE
                "rwt"     -> ParcelFileDescriptor.MODE_READ_WRITE or ParcelFileDescriptor.MODE_CREATE or
                        ParcelFileDescriptor.MODE_TRUNCATE

                else      -> throw IllegalArgumentException()
            }
            val file = getFileAndTypeForUri(uri).first
            return ParcelFileDescriptor.open(file, openMode)
        }
    }
}
