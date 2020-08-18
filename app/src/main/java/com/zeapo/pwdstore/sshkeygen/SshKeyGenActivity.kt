/*
 * Copyright © 2014-2020 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package com.zeapo.pwdstore.sshkeygen

import android.os.Bundle
import android.security.keystore.UserNotAuthenticatedException
import android.util.Base64
import android.view.MenuItem
import android.view.View
import android.view.inputmethod.InputMethodManager
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.edit
import androidx.core.content.getSystemService
import androidx.lifecycle.lifecycleScope
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.zeapo.pwdstore.R
import com.zeapo.pwdstore.databinding.ActivitySshKeygenBinding
import com.zeapo.pwdstore.git.config.AndroidKeystoreSshKeyType
import com.zeapo.pwdstore.git.operation.ANDROID_KEYSTORE_ALIAS_SSH_KEY
import com.zeapo.pwdstore.utils.BiometricAuthenticator
import com.zeapo.pwdstore.utils.getEncryptedPrefs
import com.zeapo.pwdstore.utils.keyguardManager
import com.zeapo.pwdstore.utils.sharedPrefs
import com.zeapo.pwdstore.utils.viewBinding
import java.io.File
import java.io.FileOutputStream
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import net.schmizz.sshj.common.Buffer
import net.schmizz.sshj.common.KeyType

class SshKeyGenActivity : AppCompatActivity() {

    private var keyType = AndroidKeystoreSshKeyType.Ecdsa384
    private val binding by viewBinding(ActivitySshKeygenBinding::inflate)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(binding.root)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        with(binding) {
            generate.setOnClickListener {
                lifecycleScope.launch { generate() }
            }
            keyLengthGroup.check(R.id.key_type_ecdsa)
            keyLengthGroup.addOnButtonCheckedListener { _, checkedId, isChecked ->
                if (isChecked) {
                    when (checkedId) {
                        R.id.key_type_ecdsa -> AndroidKeystoreSshKeyType.Ecdsa384
                        R.id.key_type_rsa -> AndroidKeystoreSshKeyType.Rsa3072
                        else -> throw IllegalStateException("Invalid key type selection")
                    }
                }
            }
            keyRequireAuthentication.isEnabled = keyguardManager.isDeviceSecure
            keyRequireAuthentication.isChecked = keyRequireAuthentication.isEnabled
        }
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        // The back arrow in the action bar should act the same as the back button.
        return when (item.itemId) {
            android.R.id.home -> {
                onBackPressed()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun generateAndStoreKey(requireAuthentication: Boolean) {
        val keyPair = keyType.generateKeyPair(ANDROID_KEYSTORE_ALIAS_SSH_KEY, requireAuthentication)
        val keyType = KeyType.fromKey(keyPair.public)
        val rawPublicKey = Buffer.PlainBuffer().run {
            keyType.putPubKeyIntoBuffer(keyPair.public, this)
            compactData
        }
        val encodedPublicKey = Base64.encodeToString(rawPublicKey, Base64.NO_WRAP)
        val sshPublicKey = "$keyType $encodedPublicKey"
        File(filesDir, ".ssh_key").writeText("keystore")
        File(filesDir, ".ssh_key.pub").writeText(sshPublicKey)
    }

    private suspend fun generate() {
        binding.generate.apply {
            text = getString(R.string.ssh_key_gen_generating_progress)
            isEnabled = false
        }
        binding.generate.text = getString(R.string.ssh_key_gen_generating_progress)
        val e = try {
            withContext(Dispatchers.IO) {
                val requireAuthentication = binding.keyRequireAuthentication.isChecked
                if (requireAuthentication) {
                    val result = withContext(Dispatchers.Main) {
                        suspendCoroutine<BiometricAuthenticator.Result> { cont ->
                            BiometricAuthenticator.authenticate(this@SshKeyGenActivity, R.string.biometric_prompt_title_ssh_keygen) {
                                cont.resume(it)
                            }
                        }
                    }
                    if (result !is BiometricAuthenticator.Result.Success)
                        throw UserNotAuthenticatedException(getString(R.string.biometric_auth_generic_failure))
                    generateAndStoreKey(requireAuthentication)
                }
            }
            null
        } catch (e: Exception) {
            e.printStackTrace()
            e
        } finally {
            getEncryptedPrefs("git_operation").edit {
                remove("ssh_key_local_passphrase")
            }
        }
        binding.generate.apply {
            text = getString(R.string.ssh_keygen_generate)
            isEnabled = true
        }
        if (e == null) {
            val df = ShowSshKeyFragment()
            df.show(supportFragmentManager, "public_key")
            sharedPrefs.edit { putBoolean("use_generated_key", true) }
        } else {
            MaterialAlertDialogBuilder(this)
                .setTitle(getString(R.string.error_generate_ssh_key))
                .setMessage(getString(R.string.ssh_key_error_dialog_text) + e.message)
                .setPositiveButton(getString(R.string.dialog_ok)) { _, _ ->
                    finish()
                }
                .show()
        }
        hideKeyboard()
    }

    private fun hideKeyboard() {
        val imm = getSystemService<InputMethodManager>() ?: return
        var view = currentFocus
        if (view == null) {
            view = View(this)
        }
        imm.hideSoftInputFromWindow(view.windowToken, 0)
    }
}
