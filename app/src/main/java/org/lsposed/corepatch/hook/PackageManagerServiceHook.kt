package org.lsposed.corepatch.hook

import android.annotation.SuppressLint
import android.os.Build
import org.lsposed.corepatch.Config
import org.lsposed.corepatch.XposedHelper.hookAfter
import org.lsposed.corepatch.XposedHelper.hookBefore
import org.lsposed.corepatch.XposedHelper.hostClassLoader
import org.lsposed.corepatch.XposedHelper.log

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

        // Android 9-12: packages assigned to system shared UID (appId 1000)
        // inherit signature permissions available to UID 1000, regardless of signer.
        packageManagerServiceClazz.declaredMethods
            .filter {
                it.name == "grantSignaturePermission" &&
                    it.returnType == Boolean::class.javaPrimitiveType &&
                    it.parameterCount == 4
            }
            .forEach { grantMethod ->
                hookAfter(grantMethod) { callback ->
                    if (!Config.isAllowSystemUidSharedUserPermissionsEnabled() ||
                        callback.result != false
                    ) return@hookAfter

                    val requestingPackage = callback.args.getOrNull(1) ?: return@hookAfter
                    val permission = callback.args.getOrNull(2) ?: return@hookAfter
                    if (!isSignaturePermission(permission)) return@hookAfter

                    val extras = readField(requestingPackage, "mExtras") ?: return@hookAfter
                    val sharedUser = readSharedUser(extras) ?: return@hookAfter
                    if (readAppId(sharedUser) == 1000) {
                        callback.result = true
                    }
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

    private fun isSignaturePermission(permission: Any): Boolean {
        val protectionLevel = runCatching {
            (readField(permission, "protectionLevel") as? Int)
                ?: permission.javaClass.methods.firstOrNull {
                    it.name == "getProtectionLevel" && it.parameterCount == 0
                }?.invoke(permission) as? Int
        }.getOrNull() ?: return false
        return protectionLevel and 0x0f == 2
    }

    private fun readAppId(sharedUser: Any): Int? {
        listOf("userId", "appId").forEach { name ->
            (readField(sharedUser, name) as? Int)?.let { return it }
        }
        return null
    }

    private fun readSharedUser(packageSetting: Any): Any? {
        packageSetting.javaClass.methods.firstOrNull {
            it.name == "getSharedUser" && it.parameterCount == 0
        }?.let { method ->
            runCatching { method.invoke(packageSetting) }.getOrNull()?.let { return it }
        }
        return readField(packageSetting, "sharedUser")
    }

    private fun readField(instance: Any, name: String): Any? {
        var type: Class<*>? = instance.javaClass
        while (type != null) {
            val field = type.declaredFields.firstOrNull { it.name == name }
            if (field != null) {
                field.isAccessible = true
                return field.get(instance)
            }
            type = type.superclass
        }
        return null
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
