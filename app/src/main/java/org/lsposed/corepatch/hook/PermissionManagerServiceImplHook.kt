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
 * A signature permission is bypassed only when the requesting package and the package
 * that declared that permission resolve to the same non-zero shared-user appId.
 */
object PermissionManagerServiceImplHook : BaseHook() {
    override val name = "PermissionManagerServiceImplHook"

    @SuppressLint("PrivateApi")
    override fun hook() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return

        val serviceClass = hostClassLoader.loadClass(
            "com.android.server.pm.permission.PermissionManagerServiceImpl"
        )
        val shouldGrantMethod = serviceClass.declaredMethods.firstOrNull { method ->
            method.name == "shouldGrantPermissionBySignature" &&
                method.parameterCount == 2 &&
                method.returnType == Boolean::class.javaPrimitiveType
        } ?: run {
            log("[$name] shouldGrantPermissionBySignature was not found")
            return
        }

        val packageManagerIntField = findField(serviceClass, "mPackageManagerInt")
            ?: run {
                log("[$name] mPackageManagerInt was not found")
                return
            }
        packageManagerIntField.isAccessible = true

        hookAfter(shouldGrantMethod) { callback ->
            if (!Config.isBypassDigestEnabled() ||
                !Config.isBypassSharedUserEnabled() ||
                callback.result != false
            ) return@hookAfter

            val requestingPackage = callback.args.getOrNull(0) ?: return@hookAfter
            val permission = callback.args.getOrNull(1) ?: return@hookAfter
            if (!isPlainSignaturePermission(permission)) return@hookAfter

            runCatching {
                val packageManagerInt = packageManagerIntField.get(callback.thisObject)
                    ?: return@runCatching false
                val targetPackageName = invokeString(requestingPackage, "getPackageName")
                    ?: return@runCatching false
                val sourcePackageName = invokeString(permission, "getPackageName")
                    ?: return@runCatching false

                val getPackageState = packageManagerInt.javaClass.methods.firstOrNull {
                    it.name == "getPackageStateInternal" &&
                        it.parameterTypes.contentEquals(arrayOf(String::class.java))
                } ?: return@runCatching false

                val targetState = getPackageState.invoke(packageManagerInt, targetPackageName)
                    ?: return@runCatching false
                val sourceState = getPackageState.invoke(packageManagerInt, sourcePackageName)
                    ?: return@runCatching false

                val targetSharedUserId = invokeInt(targetState, "getSharedUserAppId")
                    ?: return@runCatching false
                val sourceSharedUserId = invokeInt(sourceState, "getSharedUserAppId")
                    ?: return@runCatching false

                targetSharedUserId > 0 && targetSharedUserId == sourceSharedUserId
            }.onFailure { throwable ->
                log("[$name] failed to verify shared-user permission ownership", throwable)
            }.getOrNull()?.let { sameSharedUser ->
                if (sameSharedUser) callback.result = true
            }
        }
    }

    private fun isPlainSignaturePermission(permission: Any): Boolean {
        val protectionLevel = invokeInt(permission, "getProtectionLevel")
            ?: readIntField(permission, "protectionLevel")
            ?: readIntField(permission, "mProtectionLevel")
            ?: return false
        // PROTECTION_MASK_BASE is 0x0f and PROTECTION_SIGNATURE is 2.
        // Include signature permissions carrying additional protection flags too;
        // the same shared-user appId comparison is the strict scope boundary.
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
        runCatching { findField(instance.javaClass, name)?.apply { isAccessible = true }?.getInt(instance) }
            .getOrNull()

    private fun findField(type: Class<*>, name: String): java.lang.reflect.Field? {
        var current: Class<*>? = type
        while (current != null) {
            current.declaredFields.firstOrNull { it.name == name }?.let { return it }
            current = current.superclass
        }
        return null
    }
}
