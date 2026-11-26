package org.lsposed.corepatch.hook

import android.annotation.SuppressLint
import android.os.Build
import org.lsposed.corepatch.Config
import org.lsposed.corepatch.XposedHelper.hookAfter
import org.lsposed.corepatch.XposedHelper.hostClassLoader
import org.lsposed.corepatch.XposedHelper.log

/**
 * Android 9-12 keep signature-permission decisions in PermissionManagerService.
 *
 * grantSignaturePermission() is not a PackageManagerService method on Android 9.
 * Its false result must be overridden here, before grantPermissions() decides
 * whether to persist the install permission.
 */
object PermissionManagerServiceHook : BaseHook() {
    override val name = "PermissionManagerServiceHook"

    @SuppressLint("PrivateApi")
    override fun hook() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P ||
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
        ) return

        val serviceClass = hostClassLoader.loadClass(
            "com.android.server.pm.permission.PermissionManagerService"
        )

        val grantMethod = serviceClass.declaredMethods.firstOrNull { method ->
            method.name == "grantSignaturePermission" &&
                method.returnType == Boolean::class.javaPrimitiveType &&
                method.parameterCount == 4 &&
                method.parameterTypes[0] == String::class.java
        } ?: run {
            log("[$name] grantSignaturePermission(String, Package, BasePermission, PermissionsState) was not found")
            return
        }

        grantMethod.isAccessible = true
        log("[$name] found " + grantMethod.toGenericString())

        hookAfter(grantMethod) { callback ->
            if (!Config.isAllowSystemUidSharedUserPermissionsEnabled() ||
                callback.result != false
            ) return@hookAfter

            // Android 9 signature:
            // (String permissionName, PackageParser.Package pkg,
            //  BasePermission bp, PermissionsState origPermissions)
            val requestingPackage = callback.args.getOrNull(1)
                ?: return@hookAfter
            val permission = callback.args.getOrNull(2)
                ?: return@hookAfter

            if (!isSignaturePermission(permission)) return@hookAfter

            val packageSetting = readField(requestingPackage, "mExtras")
                ?: return@hookAfter
            val sharedUser = readSharedUser(packageSetting)
                ?: return@hookAfter
            val appId = readAppId(sharedUser)
                ?: return@hookAfter

            if (appId == 1000) {
                callback.result = true
                val packageName = readString(requestingPackage, "packageName") ?: "<unknown>"
                val permissionName = readString(permission, "getName")
                    ?: readString(permission, "name")
                    ?: "<unknown>"
                log("[$name] granted " + permissionName + " to " + packageName + " (shared appId=1000)")
            }
        }
    }

    private fun isSignaturePermission(permission: Any): Boolean {
        val protectionLevel = readInt(permission, "getProtectionLevel")
            ?: readIntField(permission, "protectionLevel")
            ?: return false
        return protectionLevel and 0x0f == 2
    }

    private fun readSharedUser(packageSetting: Any): Any? {
        val method = packageSetting.javaClass.methods.firstOrNull {
            it.name == "getSharedUser" && it.parameterCount == 0
        }
        if (method != null) {
            runCatching { method.invoke(packageSetting) }.getOrNull()?.let { return it }
        }
        return readField(packageSetting, "sharedUser")
    }

    private fun readAppId(sharedUser: Any): Int? =
        readIntField(sharedUser, "userId")
            ?: readIntField(sharedUser, "appId")

    private fun readString(instance: Any, methodOrField: String): String? {
        val method = instance.javaClass.methods.firstOrNull {
            it.name == methodOrField && it.parameterCount == 0 &&
                it.returnType == String::class.java
        }
        if (method != null) {
            runCatching { method.invoke(instance) as? String }.getOrNull()?.let { return it }
        }
        return readField(instance, methodOrField) as? String
    }

    private fun readInt(instance: Any, methodName: String): Int? =
        runCatching {
            instance.javaClass.methods.firstOrNull {
                it.name == methodName && it.parameterCount == 0 &&
                    (it.returnType == Int::class.javaPrimitiveType ||
                        it.returnType == Int::class.javaObjectType)
            }?.invoke(instance) as? Int
        }.getOrNull()

    private fun readIntField(instance: Any, fieldName: String): Int? =
        readField(instance, fieldName) as? Int

    private fun readField(instance: Any, name: String): Any? {
        var type: Class<*>? = instance.javaClass
        while (type != null) {
            val field = type.declaredFields.firstOrNull { it.name == name }
            if (field != null) {
                return runCatching {
                    field.isAccessible = true
                    field.get(instance)
                }.getOrNull()
            }
            type = type.superclass
        }
        return null
    }
}
