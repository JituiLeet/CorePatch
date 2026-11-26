package org.lsposed.corepatch.hook

import android.annotation.SuppressLint
import android.os.Build
import org.lsposed.corepatch.Config
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

        val checkDowngradeVoidMethod =
            packageManagerServiceClazz.declaredMethods.first {
                it.name == "checkDowngrade" && it.returnType == Void.TYPE
            }
        hookBefore(checkDowngradeVoidMethod) { callback ->
            if (Config.isBypassDowngradeEnabled()) {
                if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.Q) {
                    val before = callback.args[0]!!
                    val packageParserPackageClazz = before.javaClass
                    val mVersionCodeField =
                        packageParserPackageClazz.declaredFields.first { it.name == "mVersionCode" }
                    val mVersionCodeMajorField =
                        packageParserPackageClazz.declaredFields.first { it.name == "mVersionCodeMajor" }
                    mVersionCodeField.set(before, 0)
                    mVersionCodeMajorField.set(before, 0)
                }
                callback.returnAndSkip(null)
            }
        }

        val isVerificationEnabledMethod =
            packageManagerServiceClazz.declaredMethods.first { it.name == "isVerificationEnabled" }
        hookBefore(isVerificationEnabledMethod) { callback ->
            if (Config.isDisableVerificationAgentEnabled()) {
                callback.returnAndSkip(false)
            }
        }

        if (Build.VERSION.SDK_INT == Build.VERSION_CODES.R && isFlyme()) {
            val checkDowngradeBooleanMethod =
                packageManagerServiceClazz.declaredMethods.first {
                    it.name == "checkDowngrade" && it.returnType == Boolean::class.java
                }
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
        } catch (_: NoSuchMethodException) {
            false
        }
    }
}
