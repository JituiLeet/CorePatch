package org.lsposed.corepatch.hook

import android.annotation.SuppressLint
import android.os.Build
import org.lsposed.corepatch.Config
import org.lsposed.corepatch.XposedHelper.hookBefore
import org.lsposed.corepatch.XposedHelper.hostClassLoader
import java.util.Arrays

object SigningDetailsHook : BaseHook() {
    override val name = "SigningDetailsHook"

    @SuppressLint("PrivateApi")
    override fun hook() {
        val signingDetailsClazz =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                hostClassLoader.loadClass("android.content.pm.SigningDetails")
            } else {
                hostClassLoader.loadClass("android.content.pm.PackageParser\$SigningDetails")
            }

        // Keep the digest bypass separate from the shared-UID bypass. In particular,
        // SHARED_USER_ID (2) must never be bypassed by the digest switch alone.
        val checkCapabilityMethod = signingDetailsClazz.getDeclaredMethod(
            "checkCapability", signingDetailsClazz, Int::class.java
        )
        hookBefore(checkCapabilityMethod) { callback ->
            if (!Config.isBypassDigestEnabled()) return@hookBefore
            val capability = callback.args[1] as? Int ?: return@hookBefore
            if (capability == 4 || capability == 16) return@hookBefore

            if (capability == 2) {
                val inSharedUserVerification = Arrays.stream(
                    Thread.currentThread().stackTrace
                ).anyMatch { it.methodName == "verifySignatures" }
                if (Config.isBypassSharedUserEnabled() && inSharedUserVerification) {
                    callback.returnAndSkip(true)
                }
                return@hookBefore
            }
            callback.returnAndSkip(true)
        }

        val checkCapabilityRecoverMethod = signingDetailsClazz.getDeclaredMethod(
            "checkCapabilityRecover", signingDetailsClazz, Int::class.java
        )
        hookBefore(checkCapabilityRecoverMethod) { callback ->
            if (!Config.isBypassDigestEnabled()) return@hookBefore
            val capability = callback.args[1] as? Int ?: return@hookBefore
            if (capability == 4 || capability == 16) return@hookBefore

            if (capability == 2) {
                val inSharedUserVerification = Arrays.stream(
                    Thread.currentThread().stackTrace
                ).anyMatch { it.methodName == "verifySignatures" }
                if (Config.isBypassSharedUserEnabled() && inSharedUserVerification) {
                    callback.returnAndSkip(true)
                }
                return@hookBefore
            }
            callback.returnAndSkip(true)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val hasCommonAncestorMethod = signingDetailsClazz.getDeclaredMethod(
                "hasCommonAncestor", signingDetailsClazz
            )
            hookBefore(hasCommonAncestorMethod) { callback ->
                if (Config.isBypassDigestEnabled() && Config.isBypassSharedUserEnabled()
                    && Arrays.stream(Thread.currentThread().stackTrace)
                        .anyMatch { it.methodName == "verifySignatures" }
                ) {
                    callback.returnAndSkip(true)
                }
            }
        }

        val signaturesMatchExactlyMethod =
            signingDetailsClazz.getDeclaredMethod("signaturesMatchExactly", signingDetailsClazz)
        hookBefore(signaturesMatchExactlyMethod) { callback ->
            if (Config.isBypassExactSignatureMatch()) {
                callback.returnAndSkip(true)
            }
        }
    }
}
