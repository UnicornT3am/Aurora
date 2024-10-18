package com.machiav3lli.fdroid.content

import com.machiav3lli.fdroid.R
import com.machiav3lli.fdroid.utility.extension.android.Android

val BooleanPrefsMeta = mapOf(
    Preferences.Key.ShowScreenshots to Pair(
        R.string.show_screenshots,
        R.string.show_screenshots_description
    ),
    Preferences.Key.ShowTrackers to Pair(
        R.string.show_trackers,
        R.string.show_trackers_description
    ),
    Preferences.Key.AltNavBarItem to Pair(
        R.string.alt_navbar_item,
        R.string.alt_navbar_item_description
    ),
    Preferences.Key.AltNewApps to Pair(
        R.string.alt_new_apps,
        R.string.alt_new_apps_description
    ),
    Preferences.Key.HideNewApps to Pair(
        R.string.hide_new_apps,
        R.string.hide_new_apps_description
    ),
    Preferences.Key.AltBlockLayout to Pair(
        R.string.alt_block_layout,
        R.string.alt_block_layout_summary
    ),
    Preferences.Key.AndroidInsteadOfSDK to Pair(
        R.string.android_instead_of_sdk,
        R.string.android_instead_of_sdk_summary
    ),
    Preferences.Key.InstallAfterSync to Pair(
        R.string.install_after_sync,
        R.string.install_after_sync_summary
    ),
    Preferences.Key.UpdateNotify to Pair(
        R.string.notify_about_updates,
        R.string.notify_about_updates_summary
    ),
    Preferences.Key.KeepInstallNotification to Pair(
        R.string.keep_install_notification,
        R.string.keep_install_notification_summary
    ),
    Preferences.Key.DisableDownloadVersionCheck to Pair(
        R.string.disable_download_version_check,
        R.string.disable_download_version_check_summary
    ),
    Preferences.Key.UpdateUnstable to Pair(
        R.string.unstable_updates,
        R.string.unstable_updates_summary
    ),
    Preferences.Key.IncompatibleVersions to Pair(
        R.string.incompatible_versions,
        R.string.incompatible_versions_summary
    ),
    Preferences.Key.DisableSignatureCheck to Pair(
        R.string.disable_signature_check,
        R.string.disable_signature_check_summary
    ),
    Preferences.Key.RootSessionInstaller to Pair(
        R.string.root_session_installer,
        R.string.root_session_installer_description
    ),
    Preferences.Key.RootAllowDowngrades to Pair(
        R.string.root_allow_downgrades,
        R.string.root_allow_downgrades_description
    ),
    Preferences.Key.RootAllowInstallingOldApps to Pair(
        R.string.root_allow_installing_old_apps,
        R.string.root_allow_installing_old_apps_description
    ),
    Preferences.Key.EnableDownloadDirectory to Pair(
        R.string.enable_download_directory,
        R.string.enable_download_directory_summary
    ),
    Preferences.Key.DownloadManager to Pair(
        R.string.download_manager,
        R.string.download_manager_summary
    ),
    Preferences.Key.DownloadShowDialog to Pair(
        R.string.download_show_dialog,
        R.string.download_show_dialog_summary
    ),
    Preferences.Key.BottomSearchBar to Pair(
        R.string.bottom_search_bar,
        R.string.bottom_search_bar_summary
    ),
    Preferences.Key.KidsMode to Pair(
        R.string.kids_mode,
        if (Preferences[Preferences.Key.KidsMode]) R.string.kids_mode_summary
        else R.string.kids_mode_summary_full
    ),
)

val NonBooleanPrefsMeta = mapOf(
    Preferences.Key.Language to R.string.prefs_language_title,
    Preferences.Key.Theme to R.string.theme,
    Preferences.Key.DefaultTab to R.string.default_tab,
    Preferences.Key.SearchApps to R.string.prefs_search_apps_description,
    Preferences.Key.UpdatedApps to R.string.prefs_updated_apps,
    Preferences.Key.NewApps to R.string.prefs_new_apps,
    Preferences.Key.AutoSync to R.string.sync_repositories_automatically,
    Preferences.Key.AutoSyncInterval to R.string.auto_sync_interval_hours,
    Preferences.Key.Installer to R.string.prefs_installer,
    Preferences.Key.ActionLockDialog to R.string.action_lock_dialog,
    Preferences.Key.DownloadDirectory to R.string.custom_download_directory,
    Preferences.Key.ReleasesCacheRetention to R.string.releases_cache_retention,
    Preferences.Key.ImagesCacheRetention to R.string.images_cache_retention,
    Preferences.Key.ProxyType to R.string.proxy_type,
    Preferences.Key.ProxyUrl to R.string.proxy_url,
    Preferences.Key.ProxyHost to R.string.proxy_host,
    Preferences.Key.ProxyPort to R.string.proxy_port,
)

val PrefsEntries = mapOf(
    Preferences.Key.Theme to mutableMapOf(
        Preferences.Theme.Light to R.string.light,
        Preferences.Theme.Dark to R.string.dark,
        Preferences.Theme.Black to R.string.amoled,
        Preferences.Theme.LightMediumContrast to R.string.light_medium_contrast,
        Preferences.Theme.DarkMediumContrast to R.string.dark_medium_contrast,
        Preferences.Theme.BlackMediumContrast to R.string.black_medium_contrast,
        Preferences.Theme.LightHighContrast to R.string.light_high_contrast,
        Preferences.Theme.DarkHighContrast to R.string.dark_high_contrast,
        Preferences.Theme.BlackHighContrast to R.string.black_high_contrast,
    ).apply {
        if (Android.sdk(29)) {
            put(Preferences.Theme.System, R.string.system)
            put(Preferences.Theme.SystemBlack, R.string.system_black)
        }
        if (Android.sdk(31)) {
            put(Preferences.Theme.Dynamic, R.string.dynamic)
            put(Preferences.Theme.DynamicLight, R.string.dynamic_light)
            put(Preferences.Theme.DynamicDark, R.string.dynamic_dark)
            put(Preferences.Theme.DynamicBlack, R.string.dynamic_black)
        }
    },
    Preferences.Key.DefaultTab to mapOf(
        Preferences.DefaultTab.Latest to R.string.latest,
        Preferences.DefaultTab.Explore to R.string.explore,
        Preferences.DefaultTab.Search to R.string.search,
        Preferences.DefaultTab.Installed to R.string.installed,
    ),
    Preferences.Key.ActionLockDialog to mapOf(
        Preferences.ActionLock.None to R.string.action_lock_none,
        Preferences.ActionLock.Device to R.string.action_lock_device,
        Preferences.ActionLock.Biometric to R.string.action_lock_biometric,
    ),
    Preferences.Key.Installer to mapOf(
        Preferences.Installer.Default to R.string.default_installer,
        Preferences.Installer.Root to R.string.root_installer,
        Preferences.Installer.Legacy to R.string.legacy_installer,
        Preferences.Installer.AM to R.string.am_installer,
    ),
    Preferences.Key.AutoSync to mapOf(
        Preferences.AutoSync.Wifi to R.string.only_on_wifi,
        Preferences.AutoSync.WifiBattery to R.string.only_on_wifi_and_battery,
        Preferences.AutoSync.Battery to R.string.only_on_battery,
        Preferences.AutoSync.Always to R.string.always,
        Preferences.AutoSync.Never to R.string.never,
    ),
    Preferences.Key.ProxyType to mapOf(
        Preferences.ProxyType.Direct to R.string.no_proxy,
        Preferences.ProxyType.Http to R.string.http_proxy,
        Preferences.ProxyType.Socks to R.string.socks_proxy,
    ),
)

val IntPrefsRanges = mapOf(
    Preferences.Key.SearchApps to 0..10000,
    Preferences.Key.UpdatedApps to 1..1000,
    Preferences.Key.NewApps to 1..300,
    Preferences.Key.AutoSyncInterval to 1..720,
    Preferences.Key.ReleasesCacheRetention to 0..365,
    Preferences.Key.ImagesCacheRetention to 0..365,
    Preferences.Key.ProxyPort to 1..65535,
)

val PrefsDependencies = mapOf(
    Preferences.Key.RootSessionInstaller to Pair(
        Preferences.Key.Installer,
        listOf(Preferences.Installer.Root)
    ),
    Preferences.Key.RootAllowDowngrades to Pair(
        Preferences.Key.Installer,
        listOf(Preferences.Installer.Root)
    ),
    Preferences.Key.RootAllowInstallingOldApps to Pair(
        Preferences.Key.Installer,
        listOf(Preferences.Installer.Root)
    ),
    Preferences.Key.DownloadDirectory to Pair(
        Preferences.Key.EnableDownloadDirectory,
        listOf(true)
    ),
    Preferences.Key.ProxyUrl to Pair(
        Preferences.Key.ProxyType,
        listOf(Preferences.ProxyType.Http)
    ),
    Preferences.Key.ProxyHost to Pair(
        Preferences.Key.ProxyType,
        listOf(Preferences.ProxyType.Socks)
    ),
    Preferences.Key.ProxyPort to Pair(
        Preferences.Key.ProxyType,
        listOf(Preferences.ProxyType.Socks)
    ),
    Preferences.Key.ActionLockDialog to Pair(
        Preferences.Key.DownloadShowDialog,
        listOf(true)
    ),
    Preferences.Key.KidsMode to Pair(
        Preferences.Key.KidsMode,
        listOf(false)
    ),
)
