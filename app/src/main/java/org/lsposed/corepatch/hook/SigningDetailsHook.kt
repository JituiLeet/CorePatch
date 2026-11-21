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

        // When shared-user signature bypass is enabled, accept every capability,
        // including PERMISSION (4) and AUTH (16). This intentionally allows
        // signature-level permissions to be granted despite a certificate mismatch.
        val checkCapabilityMethod = signingDetailsClazz.getDeclaredMethod(
            "checkCapability", signingDetailsClazz, Int::class.java
        )
        hookBefore(checkCapabilityMethod) { callback ->
            if (Config.isBypassDigestEnabled() && Config.isBypassSharedUserEnabled()) {
                callback.returnAndSkip(true)
            }
        }

        // Recovery path used by package signature reconciliation.
        val checkCapabilityRecoverMethod = signingDetailsClazz.getDeclaredMethod(
            "checkCapabilityRecover", signingDetailsClazz, Int::class.java
        )
        hookBefore(checkCapabilityRecoverMethod) { callback ->
            if (Config.isBypassDigestEnabled() && Config.isBypassSharedUserEnabled()) {
                callback.returnAndSkip(true)
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // Shared-user lineage validation in PackageManagerServiceUtils.
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
