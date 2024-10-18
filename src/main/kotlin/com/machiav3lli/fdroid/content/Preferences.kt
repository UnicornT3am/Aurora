package com.machiav3lli.fdroid.content

import android.content.Context
import android.content.SharedPreferences
import android.content.SharedPreferences.OnSharedPreferenceChangeListener
import android.os.Build
import androidx.appcompat.app.AppCompatDelegate
import com.machiav3lli.fdroid.FILTER_CATEGORY_ALL
import com.machiav3lli.fdroid.MainApplication
import com.machiav3lli.fdroid.PREFS_LANGUAGE
import com.machiav3lli.fdroid.PREFS_LANGUAGE_DEFAULT
import com.machiav3lli.fdroid.R
import com.machiav3lli.fdroid.entity.InstallerType
import com.machiav3lli.fdroid.entity.Order
import com.machiav3lli.fdroid.utility.extension.android.Android
import com.machiav3lli.fdroid.utility.getHasSystemInstallPermission
import com.machiav3lli.fdroid.utility.isBiometricLockAvailable
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch
import java.net.Proxy

data object Preferences : OnSharedPreferenceChangeListener {
    private lateinit var preferences: SharedPreferences

    private val mutableSubject = MutableSharedFlow<Key<*>>()
    val subject = mutableSubject.asSharedFlow()

    private val keys = sequenceOf(
        Key.Language,
        Key.AutoSync,
        Key.AutoSyncInterval,
        Key.ReleasesCacheRetention,
        Key.DownloadDirectory,
        Key.DownloadManager,
        Key.DownloadShowDialog,
        Key.ActionLockDialog,
        Key.EnableDownloadDirectory,
        Key.ImagesCacheRetention,
        Key.InstallAfterSync,
        Key.IncompatibleVersions,
        Key.DisableSignatureCheck,
        Key.ShowScreenshots,
        Key.ShowTrackers,
        Key.AltNavBarItem,
        Key.AltNewApps,
        Key.HideNewApps,
        Key.AltBlockLayout,
        Key.AndroidInsteadOfSDK,
        Key.BottomSearchBar,
        Key.SearchApps,
        Key.UpdatedApps,
        Key.NewApps,
        Key.ProxyUrl,
        Key.ProxyHost,
        Key.ProxyPort,
        Key.ProxyType,
        Key.Installer,
        Key.RootSessionInstaller,
        Key.RootAllowDowngrades,
        Key.RootAllowInstallingOldApps,
        Key.SortOrderExplore,
        Key.SortOrderLatest,
        Key.SortOrderInstalled,
        Key.SortOrderSearch,
        Key.SortOrderAscendingExplore,
        Key.SortOrderAscendingLatest,
        Key.SortOrderAscendingInstalled,
        Key.SortOrderAscendingSearch,
        Key.ReposFilterExplore,
        Key.ReposFilterLatest,
        Key.ReposFilterInstalled,
        Key.ReposFilterSearch,
        Key.CategoriesFilterExplore,
        Key.CategoriesFilterLatest,
        Key.CategoriesFilterInstalled,
        Key.CategoriesFilterSearch,
        Key.AntifeaturesFilterExplore,
        Key.AntifeaturesFilterLatest,
        Key.AntifeaturesFilterInstalled,
        Key.AntifeaturesFilterSearch,
        Key.LicensesFilterExplore,
        Key.LicensesFilterLatest,
        Key.LicensesFilterInstalled,
        Key.LicensesFilterSearch,
        Key.Theme,
        Key.DefaultTab,
        Key.UpdateNotify,
        Key.KeepInstallNotification,
        Key.DisableDownloadVersionCheck,
        Key.UpdateUnstable,
        Key.KidsMode,
        // invisible values
        Key.IgnoreDisableBatteryOptimization,
        Key.IgnoreShowNotifications,
    ).map { Pair(it.name, it) }.toMap()

    fun init(context: Context) {
        preferences =
            context.getSharedPreferences(
                "${context.packageName}_preferences",
                Context.MODE_PRIVATE
            )
        preferences.registerOnSharedPreferenceChangeListener(this)
    }

    override fun onSharedPreferenceChanged(sharedPreferences: SharedPreferences?, key: String?) {
        CoroutineScope(Dispatchers.Default).launch {
            keys[key]?.let {
                mutableSubject.emit(it)
            }
        }
    }

    sealed class Value<T> {
        abstract val value: T

        internal abstract fun get(
            preferences: SharedPreferences,
            key: String,
            defaultValue: Value<T>,
        ): T

        internal abstract fun set(preferences: SharedPreferences, key: String, value: T)

        class BooleanValue(override val value: Boolean) : Value<Boolean>() {
            override fun get(
                preferences: SharedPreferences,
                key: String,
                defaultValue: Value<Boolean>,
            ): Boolean {
                return preferences.getBoolean(key, defaultValue.value)
            }

            override fun set(preferences: SharedPreferences, key: String, value: Boolean) {
                preferences.edit().putBoolean(key, value).apply()
            }
        }

        class IntValue(override val value: Int) : Value<Int>() {
            override fun get(
                preferences: SharedPreferences,
                key: String,
                defaultValue: Value<Int>,
            ): Int {
                return preferences.getInt(key, defaultValue.value)
            }

            override fun set(preferences: SharedPreferences, key: String, value: Int) {
                preferences.edit().putInt(key, value).apply()
            }
        }

        class LongValue(override val value: Long) : Value<Long>() {
            override fun get(
                preferences: SharedPreferences,
                key: String,
                defaultValue: Value<Long>,
            ): Long {
                return preferences.getLong(key, defaultValue.value)
            }

            override fun set(preferences: SharedPreferences, key: String, value: Long) {
                preferences.edit().putLong(key, value).apply()
            }
        }

        class StringSetValue(override val value: Set<String>) : Value<Set<String>>() {
            override fun get(
                preferences: SharedPreferences,
                key: String,
                defaultValue: Value<Set<String>>,
            ): Set<String> {
                return preferences.getStringSet(key, defaultValue.value) ?: emptySet()
            }

            override fun set(preferences: SharedPreferences, key: String, value: Set<String>) {
                preferences.edit().putStringSet(key, value).apply()
            }
        }

        class StringValue(override val value: String) : Value<String>() {
            override fun get(
                preferences: SharedPreferences,
                key: String,
                defaultValue: Value<String>,
            ): String {
                return preferences.getString(key, defaultValue.value) ?: defaultValue.value
            }

            override fun set(preferences: SharedPreferences, key: String, value: String) {
                preferences.edit().putString(key, value).apply()
            }
        }

        class EnumerationValue<T : Enumeration<T>>(override val value: T) : Value<T>() {
            override fun get(
                preferences: SharedPreferences,
                key: String,
                defaultValue: Value<T>,
            ): T {
                val value = preferences.getString(key, defaultValue.value.valueString)
                return defaultValue.value.values.find { it.valueString == value }
                    ?: defaultValue.value
            }

            override fun set(preferences: SharedPreferences, key: String, value: T) {
                preferences.edit().putString(key, value.valueString).apply()
            }
        }
    }

    interface Enumeration<T> {
        val values: List<T>
        val valueString: String
    }

    sealed class Key<T>(val name: String, val default: Value<T>) {
        data object Null : Key<Int>("", Value.IntValue(0))

        data object Language :
            Key<String>(PREFS_LANGUAGE, Value.StringValue(PREFS_LANGUAGE_DEFAULT))

        data object AutoSync : Key<Preferences.AutoSync>(
            "auto_sync",
            Value.EnumerationValue(Preferences.AutoSync.Wifi)
        )

        data object EnableDownloadDirectory :
            Key<Boolean>("download_directory_enable", Value.BooleanValue(false))

        data object DownloadManager :
            Key<Boolean>("download_manager", Value.BooleanValue(false))

        data object DownloadDirectory :
            Key<String>("download_directory_value", Value.StringValue(""))

        data object DownloadShowDialog :
            Key<Boolean>("download_show_dialog", Value.BooleanValue(false))

        data object ActionLockDialog :
            Key<ActionLock>("action_lock", Value.EnumerationValue(ActionLock.None))

        data object ReleasesCacheRetention : Key<Int>("releases_cache_retention", Value.IntValue(1))

        data object ImagesCacheRetention : Key<Int>("images_cache_retention", Value.IntValue(14))

        data object AutoSyncInterval : Key<Int>("auto_sync_interval_hours", Value.IntValue(4))

        data object KeepInstallNotification :
            Key<Boolean>("keep_install_notification", Value.BooleanValue(false))

        data object InstallAfterSync :
            Key<Boolean>("auto_sync_install", Value.BooleanValue(Android.sdk(31)))

        data object IncompatibleVersions :
            Key<Boolean>("incompatible_versions", Value.BooleanValue(false))

        data object DisableDownloadVersionCheck :
            Key<Boolean>("disable_download_version_check", Value.BooleanValue(false))

        data object DisableSignatureCheck :
            Key<Boolean>("disable_signature_check", Value.BooleanValue(false))

        data object ShowScreenshots :
            Key<Boolean>("show_screenshots", Value.BooleanValue(true))

        data object ShowTrackers : Key<Boolean>("show_trackers", Value.BooleanValue(true))

        data object AltNavBarItem : Key<Boolean>("alt_navbar_item", Value.BooleanValue(false))
        data object AltNewApps : Key<Boolean>("alt_new_apps_layout", Value.BooleanValue(false))
        data object HideNewApps : Key<Boolean>("hide_new_apps", Value.BooleanValue(false))
        data object AltBlockLayout : Key<Boolean>("alt_block_layout", Value.BooleanValue(false))
        data object AndroidInsteadOfSDK : Key<Boolean>("android_instead_of_sdk", Value.BooleanValue(true))
        data object BottomSearchBar : Key<Boolean>("bottom_search_bar", Value.BooleanValue(false))

        data object UpdatedApps : Key<Int>("updated_apps", Value.IntValue(150))
        data object SearchApps : Key<Int>("search_apps_num", Value.IntValue(0))
        data object NewApps : Key<Int>("new_apps", Value.IntValue(30))

        data object ProxyUrl : Key<String>("proxy_url", Value.StringValue(""))
        data object ProxyHost : Key<String>("proxy_host", Value.StringValue("localhost"))
        data object ProxyPort : Key<Int>("proxy_port", Value.IntValue(9050))
        data object ProxyType : Key<Preferences.ProxyType>(
            "proxy_type",
            Value.EnumerationValue(Preferences.ProxyType.Direct)
        )

        data object Installer : Key<Preferences.Installer>(
            "installer_type",
            Value.EnumerationValue(Preferences.Installer.Default)
        )

        data object RootSessionInstaller :
            Key<Boolean>(
                "root_session_installer",
                Value.BooleanValue(Android.sdk(Build.VERSION_CODES.TIRAMISU))
            )

        data object RootAllowDowngrades :
            Key<Boolean>(
                "root_allow_downgrades",
                Value.BooleanValue(false)
            )

        data object RootAllowInstallingOldApps :
            Key<Boolean>(
                "root_allow_low_target_sdk",
                Value.BooleanValue(false)
            )

        data object SortOrderExplore : Key<SortOrder>(
            "sort_order_explore",
            Value.EnumerationValue(SortOrder.Update)
        )

        data object SortOrderLatest : Key<SortOrder>(
            "sort_order_latest_fix",
            Value.EnumerationValue(SortOrder.Update)
        )

        data object SortOrderInstalled : Key<SortOrder>(
            "sort_order_installed",
            Value.EnumerationValue(SortOrder.Update)
        )

        data object SortOrderSearch : Key<SortOrder>(
            "sort_order_search",
            Value.EnumerationValue(SortOrder.Update)
        )

        data object SortOrderAscendingExplore :
            Key<Boolean>("sort_order_ascending_explore", Value.BooleanValue(false))

        data object SortOrderAscendingLatest :
            Key<Boolean>("sort_order_ascending_latest", Value.BooleanValue(false))

        data object SortOrderAscendingInstalled :
            Key<Boolean>("sort_order_ascending_installed", Value.BooleanValue(false))

        data object SortOrderAscendingSearch :
            Key<Boolean>("sort_order_ascending_search", Value.BooleanValue(false))

        data object ReposFilterExplore : Key<Set<String>>(
            "repos_filter_explore",
            Value.StringSetValue(emptySet())
        )

        data object ReposFilterLatest : Key<Set<String>>(
            "repos_filter_latest",
            Value.StringSetValue(emptySet())
        )

        data object ReposFilterInstalled : Key<Set<String>>(
            "repos_filter_installed",
            Value.StringSetValue(emptySet())
        )

        data object ReposFilterSearch : Key<Set<String>>(
            "repos_filter_search",
            Value.StringSetValue(emptySet())
        )

        data object CategoriesFilterExplore : Key<String>(
            "category_filter_explore_fix",
            Value.StringValue("")
        )

        data object CategoriesFilterLatest : Key<String>(
            "category_filter_latest",
            Value.StringValue(FILTER_CATEGORY_ALL)
        )

        data object CategoriesFilterInstalled : Key<String>(
            "category_filter_installed",
            Value.StringValue(FILTER_CATEGORY_ALL)
        )

        data object CategoriesFilterSearch : Key<String>(
            "category_filter_search",
            Value.StringValue(FILTER_CATEGORY_ALL)
        )

        data object AntifeaturesFilterExplore : Key<Set<String>>(
            "antifeatures_filter_explore",
            Value.StringSetValue(emptySet())
        )

        data object AntifeaturesFilterLatest : Key<Set<String>>(
            "antifeatures_filter_latest",
            Value.StringSetValue(emptySet())
        )

        data object AntifeaturesFilterInstalled : Key<Set<String>>(
            "antifeatures_filter_installed",
            Value.StringSetValue(emptySet())
        )

        data object AntifeaturesFilterSearch : Key<Set<String>>(
            "antifeatures_filter_search",
            Value.StringSetValue(emptySet())
        )

        data object LicensesFilterExplore : Key<Set<String>>(
            "licenses_filter_explore",
            Value.StringSetValue(emptySet())
        )

        data object LicensesFilterLatest : Key<Set<String>>(
            "licenses_filter_latest",
            Value.StringSetValue(emptySet())
        )

        data object LicensesFilterInstalled : Key<Set<String>>(
            "licenses_filter_installed",
            Value.StringSetValue(emptySet())
        )

        data object LicensesFilterSearch : Key<Set<String>>(
            "licenses_filter_search",
            Value.StringSetValue(emptySet())
        )

        data object Theme : Key<Preferences.Theme>(
            "theme", Value.EnumerationValue(
                when {
                    Android.sdk(31) -> Preferences.Theme.Dynamic
                    Android.sdk(29) -> Preferences.Theme.SystemBlack
                    else            -> Preferences.Theme.Light
                }
            )
        )

        data object DefaultTab : Key<Preferences.DefaultTab>(
            "default_tab_int", Value.EnumerationValue(
                Preferences.DefaultTab.Latest
            )
        )

        data object UpdateNotify : Key<Boolean>("update_notify", Value.BooleanValue(true))
        data object UpdateUnstable : Key<Boolean>("update_unstable", Value.BooleanValue(false))
        data object KidsMode : Key<Boolean>("kids_mode", Value.BooleanValue(false))

        data object IgnoreDisableBatteryOptimization :
            Key<Boolean>("ignore_disable_battery_optimization", Value.BooleanValue(false))

        data object IgnoreShowNotifications :
            Key<Boolean>("ignore_show_notifications", Value.BooleanValue(false))

        data object LastManualSyncTime :
            Key<Long>("last_manual_sync_time", Value.LongValue(0L))
    }

    sealed class AutoSync(override val valueString: String) : Enumeration<AutoSync> {
        override val values: List<AutoSync>
            get() = listOf(Never, Wifi, WifiBattery, Battery, Always)

        data object Never : AutoSync("never")
        data object Wifi : AutoSync("wifi")
        data object WifiBattery : AutoSync("wifi-battery")
        data object Battery : AutoSync("battery")
        data object Always : AutoSync("always")
    }

    sealed class ProxyType(override val valueString: String, val proxyType: Proxy.Type) :
        Enumeration<ProxyType> {
        override val values: List<ProxyType>
            get() = listOf(Direct, Http, Socks)

        data object Direct : ProxyType("direct", Proxy.Type.DIRECT)
        data object Http : ProxyType("http", Proxy.Type.HTTP)
        data object Socks : ProxyType("socks", Proxy.Type.SOCKS)
    }

    sealed class SortOrder(override val valueString: String, val order: Order) :
        Enumeration<SortOrder> {
        override val values: List<SortOrder>
            get() = listOf(Name, Added, Update)

        data object Name : SortOrder("name", Order.NAME)
        data object Added : SortOrder("added", Order.DATE_ADDED)
        data object Update : SortOrder("update", Order.LAST_UPDATE)
    }

    sealed class Installer(override val valueString: String, val installer: InstallerType) :
        Enumeration<Installer> {
        override val values: List<Installer>
            get() = mutableListOf(Default, Root, AM, Legacy).apply {
                if (MainApplication.context.getHasSystemInstallPermission())
                    add(System)
            }

        data object Default : Installer("session", InstallerType.DEFAULT)
        data object Root : Installer("root", InstallerType.ROOT)
        data object AM : Installer("app_manager", InstallerType.AM)
        data object Legacy : Installer("legacy", InstallerType.LEGACY)
        data object System : Installer("system", InstallerType.SYSTEM)
    }

    sealed class ActionLock(override val valueString: String, val order: Order) :
        Enumeration<ActionLock> {
        override val values: List<ActionLock>
            get() = mutableListOf(None, Device).apply {
                if (MainApplication.context.isBiometricLockAvailable())
                    add(Biometric)
            }

        data object None : ActionLock("none", Order.NAME)
        data object Device : ActionLock("device", Order.DATE_ADDED)
        data object Biometric : ActionLock("biometric", Order.LAST_UPDATE)
    }

    sealed class Theme(override val valueString: String) : Enumeration<Theme> {
        override val values: List<Theme>
            get() = mutableListOf(
                Light,
                Dark,
                Black,
                LightMediumContrast,
                DarkMediumContrast,
                BlackMediumContrast,
                LightHighContrast,
                DarkHighContrast,
                BlackHighContrast,
            ).apply {
                if (Android.sdk(31)) addAll(
                    listOf(
                        Dynamic,
                        DynamicLight,
                        DynamicDark,
                        DynamicBlack
                    )
                )
                if (Android.sdk(29)) addAll(listOf(System, SystemBlack))
            }

        abstract val resId: Int
        abstract val nightMode: Int

        data object System : Theme("system") {
            override val resId: Int
                get() = R.style.Theme_Main
            override val nightMode: Int
                get() = AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
        }

        data object SystemBlack : Theme("system-amoled") {
            override val resId: Int
                get() = R.style.Theme_Main_Amoled
            override val nightMode: Int
                get() = AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
        }

        data object Dynamic : Theme("dynamic-system") {
            override val resId: Int
                get() = -1
            override val nightMode: Int
                get() = AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
        }

        data object DynamicLight : Theme("dynamic-light") {
            override val resId: Int
                get() = -1
            override val nightMode: Int
                get() = AppCompatDelegate.MODE_NIGHT_NO
        }

        data object DynamicDark : Theme("dynamic-dark") {
            override val resId: Int
                get() = -1
            override val nightMode: Int
                get() = AppCompatDelegate.MODE_NIGHT_YES
        }

        data object DynamicBlack : Theme("dynamic-black") {
            override val resId: Int
                get() = -1
            override val nightMode: Int
                get() = AppCompatDelegate.MODE_NIGHT_YES
        }

        data object Light : Theme("light") {
            override val resId: Int
                get() = R.style.Theme_Main
            override val nightMode: Int
                get() = AppCompatDelegate.MODE_NIGHT_NO
        }

        data object LightMediumContrast : Theme("light_medium_contrast") {
            override val resId: Int
                get() = R.style.Theme_Main
            override val nightMode: Int
                get() = AppCompatDelegate.MODE_NIGHT_NO
        }

        data object LightHighContrast : Theme("light_high_contrast") {
            override val resId: Int
                get() = R.style.Theme_Main
            override val nightMode: Int
                get() = AppCompatDelegate.MODE_NIGHT_NO
        }

        data object Dark : Theme("dark") {
            override val resId: Int
                get() = R.style.Theme_Main
            override val nightMode: Int
                get() = AppCompatDelegate.MODE_NIGHT_YES
        }

        data object DarkMediumContrast : Theme("dark_medium_contrast") {
            override val resId: Int
                get() = R.style.Theme_Main
            override val nightMode: Int
                get() = AppCompatDelegate.MODE_NIGHT_YES
        }

        data object DarkHighContrast : Theme("dark_high_contrast") {
            override val resId: Int
                get() = R.style.Theme_Main
            override val nightMode: Int
                get() = AppCompatDelegate.MODE_NIGHT_YES
        }

        data object Black : Theme("amoled") {
            override val resId: Int
                get() = R.style.Theme_Main_Amoled
            override val nightMode: Int
                get() = AppCompatDelegate.MODE_NIGHT_YES
        }

        data object BlackMediumContrast : Theme("black_medium_contrast") {
            override val resId: Int
                get() = R.style.Theme_Main_Amoled
            override val nightMode: Int
                get() = AppCompatDelegate.MODE_NIGHT_YES
        }

        data object BlackHighContrast : Theme("black_high_contrast") {
            override val resId: Int
                get() = R.style.Theme_Main_Amoled
            override val nightMode: Int
                get() = AppCompatDelegate.MODE_NIGHT_YES
        }
    }

    sealed class DefaultTab(override val valueString: String) : Enumeration<DefaultTab> {
        override val values: List<DefaultTab>
            get() = listOf(Latest, Explore, Search, Installed)

        val index get() = valueString.toInt()

        data object Latest : DefaultTab("0")
        data object Explore : DefaultTab("1")
        data object Search : DefaultTab("2")
        data object Installed : DefaultTab("3")
    }

    operator fun <T> get(key: Key<T>): T {
        return key.default.get(preferences, key.name, key.default)
    }

    operator fun <T> set(key: Key<T>, value: T) {
        key.default.set(preferences, key.name, value)
    }
}
