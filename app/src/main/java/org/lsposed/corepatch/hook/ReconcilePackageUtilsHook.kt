package org.lsposed.corepatch.hook

import android.annotation.SuppressLint
import android.os.Build
import org.lsposed.corepatch.Config
import org.lsposed.corepatch.XposedHelper
import org.lsposed.corepatch.XposedHelper.hostClassLoader
import org.lsposed.corepatch.XposedHelper.hookBefore
import org.lsposed.corepatch.XposedHelper.log
import org.lsposed.corepatch.XposedHelper.setStaticBoolean

object ReconcilePackageUtilsHook : BaseHook() {
    override val name = "ReconcilePackageUtilsHook"

    @SuppressLint("PrivateApi")
    override fun hook() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return

        val reconcilePackageUtilsClazz =
            hostClassLoader.loadClass("com.android.server.pm.ReconcilePackageUtils")
        val reconcilePackagesMethod =
            reconcilePackageUtilsClazz.declaredMethods.first { method ->
                method.name == "reconcilePackages"
            }
        if (!XposedHelper.deoptimize(reconcilePackagesMethod)) {
            log("failed to deoptimize reconcilePackages")
        }

        // Android 15+ rejects non-preload apps joining platform-signed shared UIDs
        // unless they appear in the device allowlist. The field is initialized once
        // by the framework, so update it immediately before each reconciliation to
        // follow the live CorePatch setting rather than only the boot-time setting.
        val allowNonPreloadsField = reconcilePackageUtilsClazz.declaredFields
            .firstOrNull { field ->
                field.name == "ALLOW_NON_PRELOADS_SYSTEM_SHAREDUIDS"
            }
            ?.apply { isAccessible = true }
        val originalAllowNonPreloads = allowNonPreloadsField?.let { field ->
            runCatching { field.getBoolean(null) }.getOrNull()
        }

        if (allowNonPreloadsField != null && originalAllowNonPreloads != null) {
            hookBefore(reconcilePackagesMethod) {
                val bypassSharedUser =
                    Config.isBypassDigestEnabled() && Config.isBypassSharedUserEnabled()
                setStaticBoolean(
                    allowNonPreloadsField,
                    bypassSharedUser || originalAllowNonPreloads
                )
            }
        }
    }
}
