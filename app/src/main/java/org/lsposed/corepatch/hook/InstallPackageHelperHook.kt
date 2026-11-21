package org.lsposed.corepatch.hook

import android.annotation.SuppressLint
import android.os.Build
import org.lsposed.corepatch.Config
import org.lsposed.corepatch.XposedHelper.hookAfter
import org.lsposed.corepatch.XposedHelper.hostClassLoader

object InstallPackageHelperHook : BaseHook() {
    override val name = "InstallPackageHelperHook"

    @SuppressLint("PrivateApi")
    override fun hook() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return

        val installPackageHelperClazz =
            hostClassLoader.loadClass("com.android.server.pm.InstallPackageHelper")
        val doesSignatureMatchForPermissionsMethod =
            installPackageHelperClazz.declaredMethods.first { m -> m.name == "doesSignatureMatchForPermissions" }
        hookAfter(doesSignatureMatchForPermissionsMethod) hook@{ callback ->
            if (!Config.isBypassDigestEnabled() || !Config.isBypassSharedUserEnabled()) {
                return@hook
            }
            // Do not retain the previous-signature or same-package restrictions:
            // the requested shared-UID bypass explicitly grants signature permissions
            // even when the shared UID's existing signer is different.
            callback.result = true
        }
    }
undefined}
