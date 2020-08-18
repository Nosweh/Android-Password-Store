/*
 * Copyright © 2014-2020 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package com.zeapo.pwdstore.git.config

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import com.github.ajalt.timberkt.e
import com.github.ajalt.timberkt.i
import net.schmizz.sshj.common.KeyType
import net.schmizz.sshj.userauth.keyprovider.KeyProvider
import java.io.IOException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.UnrecoverableKeyException


const val PROVIDER_ANDROID_KEYSTORE = "AndroidKeyStore"
// Maximal time between dismissing the `BiometricPrompt` and authentication the SSH session
private const val USER_AUTHENTICATION_TIMEOUT_S = 30

private val androidKeystore: KeyStore by lazy {
    KeyStore.getInstance(PROVIDER_ANDROID_KEYSTORE).apply { load(null) }
}

private fun KeyStore.getPrivateKey(keyAlias: String) = getKey(keyAlias, null) as? PrivateKey

private fun KeyStore.getPublicKey(keyAlias: String) = getCertificate(keyAlias)?.publicKey

enum class AndroidKeystoreSshKeyType(private val algorithm: String, private val keyLength: Int,
                                     private val applyToSpec: KeyGenParameterSpec.Builder.() -> Unit) {

    Rsa2048(KeyProperties.KEY_ALGORITHM_RSA, 2048, {
        setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
        setDigests(KeyProperties.DIGEST_SHA1, KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
    }),
    Rsa3072(KeyProperties.KEY_ALGORITHM_RSA, 3072, {
        setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
        setDigests(KeyProperties.DIGEST_SHA1, KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
    }),
    Rsa4096(KeyProperties.KEY_ALGORITHM_RSA, 4096, {
        setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
        setDigests(KeyProperties.DIGEST_SHA1, KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
    }),
    Ecdsa256(KeyProperties.KEY_ALGORITHM_EC, 256, {
        setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
        setDigests(KeyProperties.DIGEST_SHA256)
    }),
    Ecdsa384(KeyProperties.KEY_ALGORITHM_EC, 384, {
        setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp384r1"))
        setDigests(KeyProperties.DIGEST_SHA384)
    }),
    Ecdsa521(KeyProperties.KEY_ALGORITHM_EC, 521, {
        setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp521r1"))
        setDigests(KeyProperties.DIGEST_SHA512)
    });

    fun generateKeyPair(keyAlias: String, requireAuthentication: Boolean): KeyPair {
        val parameterSpec = KeyGenParameterSpec.Builder(
            keyAlias, KeyProperties.PURPOSE_SIGN
        ).run {
            setKeySize(keyLength)
            apply(applyToSpec)
            if (requireAuthentication) {
                setUserAuthenticationRequired(true)
                setUserAuthenticationValidityDurationSeconds(USER_AUTHENTICATION_TIMEOUT_S)
            }
            build()
        }
        return KeyPairGenerator.getInstance(algorithm, PROVIDER_ANDROID_KEYSTORE).run {
            initialize(parameterSpec)
            generateKeyPair()
        }
    }
}


class AndroidKeystoreKeyProvider(private val keyAlias: String) : KeyProvider {

    override fun getPublic(): PublicKey = try {
        androidKeystore.getPublicKey(keyAlias)!!
    } catch (error: Exception) {
        e(error)
        throw IOException("Failed to get public key '$keyAlias' from Android Keystore")
    }

    override fun getType(): KeyType = KeyType.fromKey(public)

    override fun getPrivate(): PrivateKey = try {
        androidKeystore.getPrivateKey(keyAlias)!!
    } catch (error: Exception) {
        e(error)
        throw IOException("Failed to access private key '$keyAlias' from Android Keystore")
    }

    companion object {
        fun isUserAuthenticationRequired(keyAlias: String): Boolean? {
            return try {
                val key = androidKeystore.getPrivateKey(keyAlias) ?: return null
                val factory = KeyFactory.getInstance(key.algorithm, PROVIDER_ANDROID_KEYSTORE)
                factory.getKeySpec(key, KeyInfo::class.java).isUserAuthenticationRequired
            } catch (error: Exception) {
                if (error is KeyPermanentlyInvalidatedException || error is UnrecoverableKeyException) {
                    // The user deactivated their screen lock, which invalidates the key. We delete
                    // it and pretend we didn't find it.
                    androidKeystore.deleteEntry(keyAlias)
                    return null
                }
                // It is fine to swallow the exception here since it will reappear when the key is
                // used for authentication and can then be shown in the UI.
                true
            }
        }
    }
}
