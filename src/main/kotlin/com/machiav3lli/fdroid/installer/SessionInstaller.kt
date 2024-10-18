package com.machiav3lli.fdroid.installer

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.content.pm.PackageInstaller.SessionParams
import android.util.Log
import com.machiav3lli.fdroid.NeoActivity
import com.machiav3lli.fdroid.content.Cache
import com.machiav3lli.fdroid.content.Cache.getPackageArchiveInfo
import com.machiav3lli.fdroid.content.Preferences
import com.machiav3lli.fdroid.service.InstallerReceiver
import com.machiav3lli.fdroid.utility.extension.android.Android
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException

class SessionInstaller(context: Context) : BaseInstaller(context) {

    private val packageManager = context.packageManager
    private val sessionInstaller = packageManager.packageInstaller
    private val intent = Intent(context, InstallerReceiver::class.java)

    companion object {
        val flags =
            if (Android.sdk(31)) PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            else PendingIntent.FLAG_UPDATE_CURRENT
        val sessionParams = SessionParams(SessionParams.MODE_FULL_INSTALL).apply {
            if (Android.sdk(31)) {
                setRequireUserAction(SessionParams.USER_ACTION_NOT_REQUIRED)
            }
            if (Android.sdk(33)) {
                setPackageSource(PackageInstaller.PACKAGE_SOURCE_STORE)
            }
        }
    }

    override suspend fun install(
        packageLabel: String,
        cacheFileName: String,
        postInstall: () -> Unit
    ) {
        val cacheFile = Cache.getReleaseFile(context, cacheFileName)
        // using packageName to store the app's name for the notification later down the line
        intent.putExtra(InstallerReceiver.KEY_PACKAGE_LABEL, packageLabel)
        intent.putExtra(NeoActivity.EXTRA_CACHE_FILE_NAME, cacheFileName)
        mDefaultInstaller(cacheFile, postInstall)
    }

    override suspend fun isInstalling(packageName: String): Boolean =
        sessionInstaller.mySessions.any { (!Android.sdk(29) || it.isStaged) && it.appPackageName == packageName }

    override suspend fun uninstall(packageName: String) = mDefaultUninstaller(packageName)

    private fun mDefaultInstaller(cacheFile: File, postInstall: () -> Unit) {
        // clean up inactive sessions
        sessionInstaller.mySessions
            .filter { session -> !session.isActive }
            .forEach { session ->
                try {
                    sessionInstaller.abandonSession(session.sessionId)
                } catch (_: SecurityException) {
                    Log.w(
                        "SessionInstaller",
                        "Attempted to abandon a session we do not own."
                    )
                }
            }

        // start new session
        val id = sessionInstaller.createSession(sessionParams)
        val session = sessionInstaller.openSession(id)

        // get package name
        val packageInfo = context.getPackageArchiveInfo(cacheFile)
        val packageName = packageInfo?.packageName ?: "unknown-package"

        // error flags
        var hasErrors = false

        session.use { activeSession ->
            try {
                val sessionOutputStream = activeSession.openWrite(packageName, 0, -1)
                val packageInputStream = cacheFile.inputStream()
                packageInputStream.copyTo(sessionOutputStream)

                packageInputStream.close()
                sessionOutputStream.flush()
                sessionOutputStream.close()
            } catch (e: FileNotFoundException) {
                Log.w(
                    "SessionInstaller",
                    "Cache file does not seem to exist.\n${e.message}"
                )
                hasErrors = true
            } catch (e: SecurityException) {
                Log.w(
                    "SessionInstaller",
                    "Attempted to use a destroyed or sealed session when installing.\n${e.message}"
                )
                hasErrors = true
            } catch (e: IOException) {
                Log.w(
                    "SessionInstaller",
                    "Failed to perform cache to package copy due to a bad pipe.\n${e.message}"
                )
                hasErrors = true
            } finally {
                intent.putExtra(PackageInstaller.EXTRA_PACKAGE_NAME, packageName)
                if (!hasErrors) {
                    session.commit(
                        PendingIntent.getBroadcast(context, id, intent, flags).intentSender
                    )
                    if (Preferences[Preferences.Key.ReleasesCacheRetention] == 0) cacheFile.delete()
                    postInstall()
                }
            }
        }
    }

    private suspend fun mDefaultUninstaller(packageName: String) {
        intent.putExtra(InstallerReceiver.KEY_ACTION, InstallerReceiver.ACTION_UNINSTALL)

        val pendingIntent = PendingIntent.getBroadcast(context, -1, intent, flags)

        withContext(Dispatchers.Default) {
            sessionInstaller.uninstall(packageName, pendingIntent.intentSender)
        }
    }
}