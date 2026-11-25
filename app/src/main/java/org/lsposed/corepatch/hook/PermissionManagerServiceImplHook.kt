package org.lsposed.corepatch.hook

import android.annotation.SuppressLint
import android.os.Build
import org.lsposed.corepatch.Config
import org.lsposed.corepatch.XposedHelper.hookAfter
import org.lsposed.corepatch.XposedHelper.hostClassLoader
import org.lsposed.corepatch.XposedHelper.log

/**
 * Android 13+ moved signature permission decisions into PermissionManagerServiceImpl.
 *
 * When enabled, packages assigned to system shared UID (appId 1000) may receive
 * signature permissions even when their APK signer differs from the platform.
 * The privileged-permission allowlist check is also covered because Android 13+
 * evaluates it separately while building the permission grant sets.
 */
object PermissionManagerServiceImplHook : BaseHook() {
    override val name = "PermissionManagerServiceImplHook"

    @SuppressLint("PrivateApi")
    override fun hook() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return

        val serviceClass = hostClassLoader.loadClass(
            "com.android.server.pm.permission.PermissionManagerServiceImpl"
        )

        val packageManagerIntField = findField(serviceClass, "mPackageManagerInt")
            ?: run {
                log("[$name] mPackageManagerInt was not found")
                return
            }
        packageManagerIntField.isAccessible = true

        // Android 13+ collects privileged permissions separately from the
        // signature decision. Returning true here places the permission in
        // isPrivilegedPermissionAllowlisted, so the later grant stage does not
        // discard signature|privileged permissions for UID 1000.
        val allowlistMethod = serviceClass.declaredMethods.firstOrNull { method ->
            method.name == "checkPrivilegedPermissionAllowlist" &&
                method.parameterCount == 3 &&
                method.returnType == Boolean::class.javaPrimitiveType
        }
        if (allowlistMethod == null) {
            log("[$name] checkPrivilegedPermissionAllowlist was not found")
        } else {
            hookAfter(allowlistMethod) { callback ->
                if (!Config.isAllowSystemUidSharedUserPermissionsEnabled() ||
                    callback.result == true
                ) return@hookAfter

                val requestingPackage = callback.args.getOrNull(0)
                    ?: return@hookAfter
                if (isSystemSharedUidPackage(
                        callback.thisObject,
                        packageManagerIntField,
                        requestingPackage
                    )
                ) {
                    callback.result = true
                }
            }
        }

        val shouldGrantMethod = serviceClass.declaredMethods.firstOrNull { method ->
            method.name == "shouldGrantPermissionBySignature" &&
                method.parameterCount == 2 &&
                method.returnType == Boolean::class.javaPrimitiveType
        } ?: run {
            log("[$name] shouldGrantPermissionBySignature was not found")
            return
        }

        hookAfter(shouldGrantMethod) { callback ->
            if (!Config.isAllowSystemUidSharedUserPermissionsEnabled() ||
                callback.result == true
            ) return@hookAfter

            val requestingPackage = callback.args.getOrNull(0) ?: return@hookAfter
            val permission = callback.args.getOrNull(1) ?: return@hookAfter
            if (!isSignaturePermission(permission)) return@hookAfter

            if (isSystemSharedUidPackage(
                    callback.thisObject,
                    packageManagerIntField,
                    requestingPackage
                )
            ) {
                callback.result = true
            }
        }
    }

    private fun isSystemSharedUidPackage(
        service: Any?,
        packageManagerIntField: java.lang.reflect.Field,
        requestingPackage: Any
    ): Boolean = runCatching {
        val packageManagerInt = service?.let { packageManagerIntField.get(it) }
            ?: return@runCatching false
        val packageName = invokeString(requestingPackage, "getPackageName")
            ?: return@runCatching false
        val getPackageState = packageManagerInt.javaClass.methods.firstOrNull {
            it.name == "getPackageStateInternal" &&
                it.parameterTypes.contentEquals(arrayOf(String::class.java))
        } ?: return@runCatching false

        val packageState = getPackageState.invoke(packageManagerInt, packageName)
            ?: return@runCatching false
        invokeInt(packageState, "getSharedUserAppId") == 1000
    }.onFailure { throwable ->
        log("[$name] failed to verify system shared UID", throwable)
    }.getOrDefault(false)

    private fun isSignaturePermission(permission: Any): Boolean {
        val protectionLevel = invokeInt(permission, "getProtectionLevel")
            ?: readIntField(permission, "protectionLevel")
            ?: readIntField(permission, "mProtectionLevel")
            ?: return false
        // PROTECTION_MASK_BASE is 0x0f and PROTECTION_SIGNATURE is 2.
        // Preserve additional flags such as privileged, vendorPrivileged, etc.
        return protectionLevel and 0x0f == 2
    }

    private fun invokeString(instance: Any, name: String): String? =
        runCatching {
            instance.javaClass.methods.firstOrNull {
                it.name == name && it.parameterCount == 0
            }?.invoke(instance) as? String
        }.getOrNull()

    private fun invokeInt(instance: Any, name: String): Int? =
        runCatching {
            instance.javaClass.methods.firstOrNull {
                it.name == name && it.parameterCount == 0
            }?.invoke(instance) as? Int
        }.getOrNull()

    private fun readIntField(instance: Any, name: String): Int? =
        runCatching {
            findField(instance.javaClass, name)?.apply { isAccessible = true }?.getInt(instance)
        }.getOrNull()

    private fun findField(type: Class<*>, name: String): java.lang.reflect.Field? {
        var current: Class<*>? = type
        while (current != null) {
            current.declaredFields.firstOrNull { it.name == name }?.let { return it }
            current = current.superclass
        }
        return null
    }
}
