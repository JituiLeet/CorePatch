package org.lsposed.corepatch.hook

import android.annotation.SuppressLint
import android.os.Build
import org.lsposed.corepatch.Config
import org.lsposed.corepatch.XposedHelper.hookAfter
import org.lsposed.corepatch.XposedHelper.hookBefore
import org.lsposed.corepatch.XposedHelper.hostClassLoader

object PackageManagerServiceHook : BaseHook() {
    override val name = "PackageManagerServiceHook"

    @SuppressLint("PrivateApi", "DiscouragedPrivateApi", "SoonBlockedPrivateApi")
    override fun hook() {
        if (Build.VERSION.SDK_INT > Build.VERSION_CODES.S_V2) {
            return
        }

        val packageManagerServiceClazz =
            hostClassLoader.loadClass("com.android.server.pm.PackageManagerService")

        // https://cs.android.com/android/platform/superproject/+/android-5.1.0_r5:frameworks/base/services/core/java/com/android/server/pm/PackageManagerService.java;l=13604
        // private static void checkDowngrade(PackageParser.Package before, PackageInfoLite after)
        // https://cs.android.com/android/platform/superproject/+/android-11.0.0_r48:frameworks/base/services/core/java/com/android/server/pm/PackageManagerService.java;l=23832
        // private static void checkDowngrade(AndroidPackage before, PackageInfoLite after)
        val checkDowngradeVoidMethod =
            packageManagerServiceClazz.declaredMethods.first { m -> m.name == "checkDowngrade" && m.returnType == Void.TYPE }
        hookBefore(checkDowngradeVoidMethod) { callback ->
            if (Config.isBypassDowngradeEnabled()) {
                if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.Q) {
                    val before = callback.args[0]!!
                    val packageParserPackageClazz = before.javaClass
                    val mVersionCodeField =
                        packageParserPackageClazz.declaredFields.first { f -> f.name == "mVersionCode" }
                    val mVersionCodeMajorField =
                        packageParserPackageClazz.declaredFields.first { f -> f.name == "mVersionCodeMajor" }
                    mVersionCodeField.set(before, 0)
                    mVersionCodeMajorField.set(before, 0)
                }
                callback.returnAndSkip(null)
            }
        }

        val isVerificationEnabledMethod =
            packageManagerServiceClazz.declaredMethods.first { m -> m.name == "isVerificationEnabled" }
        hookBefore(isVerificationEnabledMethod) { callback ->
            if (Config.isDisableVerificationAgentEnabled()) {
                callback.returnAndSkip(false)
            }
        }

        // Android 9-12 grant signature-level permissions through this method.
        // Bypass its signer comparison only while the shared-UID bypass is enabled.
        packageManagerServiceClazz.declaredMethods
            .filter { method ->
                method.name == "grantSignaturePermission" &&
                    method.returnType == Boolean::class.javaPrimitiveType
            }
            .forEach { grantSignaturePermissionMethod ->
                hookAfter(grantSignaturePermissionMethod) { callback ->
                    if (Config.isBypassDigestEnabled() && Config.isBypassSharedUserEnabled()) {
                        callback.result = true
                    }
                }
            }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val doesSignatureMatchForPermissionsMethod =
                packageManagerServiceClazz.declaredMethods.first { m -> m.name == "doesSignatureMatchForPermissions" }
            hookAfter(doesSignatureMatchForPermissionsMethod) { callback ->
                if (Config.isBypassDigestEnabled() && Config.isBypassSharedUserEnabled()) {
                    // Signature-level permission checks must not block a package
                    // joining a shared UID with a different signing certificate.
                    callback.result = true
                }
            }
        }

        // exists on flyme 9(Android 11) only
        if (Build.VERSION.SDK_INT == Build.VERSION_CODES.R && isFlyme()) {
            val checkDowngradeBooleanMethod =
                packageManagerServiceClazz.declaredMethods.first { m -> m.name == "checkDowngrade" && m.returnType == Boolean::class.java }
            hookBefore(checkDowngradeBooleanMethod) { callback ->
                if (Config.isBypassDowngradeEnabled()) {
                    callback.returnAndSkip(true)
                }
            }
        }
    }

    private fun isFlyme(): Boolean {
        return try {
            Build::class.java.getMethod("hasSmartBar")
            true
        } catch (e: NoSuchMethodException) {
            false
        }
    }
}
