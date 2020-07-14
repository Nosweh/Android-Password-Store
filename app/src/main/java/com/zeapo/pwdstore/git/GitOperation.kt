/*
 * Copyright © 2014-2020 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package com.zeapo.pwdstore.git

import android.annotation.SuppressLint
import android.content.Intent
import android.security.keystore.UserNotAuthenticatedException
import android.view.LayoutInflater
import android.widget.Toast
import androidx.annotation.StringRes
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.fragment.app.FragmentActivity
import androidx.preference.PreferenceManager
import com.google.android.material.checkbox.MaterialCheckBox
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.textfield.TextInputEditText
import com.zeapo.pwdstore.R
import com.zeapo.pwdstore.UserPreference
import com.zeapo.pwdstore.git.config.AndroidKeystoreKeyProvider
import com.zeapo.pwdstore.git.config.ConnectionMode
import com.zeapo.pwdstore.git.config.InteractivePasswordFinder
import com.zeapo.pwdstore.git.config.SshApiSessionFactory
import com.zeapo.pwdstore.git.config.SshAuthData
import com.zeapo.pwdstore.git.config.SshjSessionFactory
import com.zeapo.pwdstore.utils.BiometricAuthenticator
import com.zeapo.pwdstore.utils.PasswordRepository
import com.zeapo.pwdstore.utils.PreferenceKeys
import com.zeapo.pwdstore.utils.getEncryptedPrefs
import com.zeapo.pwdstore.utils.requestInputFocusOnView
import java.io.File
import kotlin.coroutines.Continuation
import kotlin.coroutines.resume
import net.schmizz.sshj.userauth.password.PasswordFinder
import org.eclipse.jgit.api.GitCommand
import org.eclipse.jgit.errors.UnsupportedCredentialItem
import org.eclipse.jgit.lib.Repository
import org.eclipse.jgit.transport.CredentialItem
import org.eclipse.jgit.transport.CredentialsProvider
import org.eclipse.jgit.transport.SshSessionFactory
import org.eclipse.jgit.transport.URIish
import com.google.android.material.R as materialR


const val ANDROID_KEYSTORE_ALIAS_SSH_KEY = "ssh_key"

private class GitOperationCredentialFinder(
    val callingActivity: AppCompatActivity,
    val connectionMode: ConnectionMode
) : InteractivePasswordFinder() {

    override fun askForPassword(cont: Continuation<String?>, isRetry: Boolean) {
        val gitOperationPrefs = callingActivity.getEncryptedPrefs("git_operation")
        val credentialPref: String
        @StringRes val messageRes: Int
        @StringRes val hintRes: Int
        @StringRes val rememberRes: Int
        @StringRes val errorRes: Int
        when (connectionMode) {
            ConnectionMode.SshKey -> {
                credentialPref = PreferenceKeys.SSH_KEY_LOCAL_PASSPHRASE
                messageRes = R.string.passphrase_dialog_text
                hintRes = R.string.ssh_keygen_passphrase
                rememberRes = R.string.git_operation_remember_passphrase
                errorRes = R.string.git_operation_wrong_passphrase
            }
            ConnectionMode.Password -> {
                // Could be either an SSH or an HTTPS password
                credentialPref = PreferenceKeys.HTTPS_PASSWORD
                messageRes = R.string.password_dialog_text
                hintRes = R.string.git_operation_hint_password
                rememberRes = R.string.git_operation_remember_password
                errorRes = R.string.git_operation_wrong_password
            }
            else -> throw IllegalStateException("Only SshKey and Password connection mode ask for passwords")
        }
        val storedCredential = gitOperationPrefs.getString(credentialPref, null)
        if (isRetry)
            gitOperationPrefs.edit { remove(credentialPref) }
        if (storedCredential == null) {
            val layoutInflater = LayoutInflater.from(callingActivity)

            @SuppressLint("InflateParams")
            val dialogView = layoutInflater.inflate(R.layout.git_credential_layout, null)
            val editCredential = dialogView.findViewById<TextInputEditText>(R.id.git_auth_credential)
            editCredential.setHint(hintRes)
            val rememberCredential = dialogView.findViewById<MaterialCheckBox>(R.id.git_auth_remember_credential)
            rememberCredential.setText(rememberRes)
            if (isRetry)
                editCredential.setError(callingActivity.resources.getString(errorRes),
                    ContextCompat.getDrawable(callingActivity, materialR.drawable.mtrl_ic_error))
            MaterialAlertDialogBuilder(callingActivity).run {
                setTitle(R.string.passphrase_dialog_title)
                setMessage(messageRes)
                setView(dialogView)
                setPositiveButton(R.string.dialog_ok) { _, _ ->
                    val credential = editCredential.text.toString()
                    if (rememberCredential.isChecked) {
                        gitOperationPrefs.edit {
                            putString(credentialPref, credential)
                        }
                    }
                    cont.resume(credential)
                }
                setNegativeButton(R.string.dialog_cancel) { _, _ ->
                    cont.resume(null)
                }
                setOnCancelListener {
                    cont.resume(null)
                }
                create()
            }.run {
                requestInputFocusOnView<TextInputEditText>(R.id.git_auth_credential)
                show()
            }
        } else {
            cont.resume(storedCredential)
        }
    }
}

/**
 * Creates a new git operation
 *
 * @param gitDir the git working tree directory
 * @param callingActivity the calling activity
 */
abstract class GitOperation(gitDir: File, internal val callingActivity: AppCompatActivity) {

    protected val repository: Repository? = PasswordRepository.getRepository(gitDir)
    internal var provider: CredentialsProvider? = null
    internal var command: GitCommand<*>? = null
    private val sshKeyFile = callingActivity.filesDir.resolve(".ssh_key")
    private val hostKeyFile = callingActivity.filesDir.resolve(".host_key")

    private class PasswordFinderCredentialsProvider(private val username: String, private val passwordFinder: PasswordFinder) : CredentialsProvider() {

        override fun isInteractive() = true

        override fun get(uri: URIish?, vararg items: CredentialItem): Boolean {
            for (item in items) {
                when (item) {
                    is CredentialItem.Username -> item.value = username
                    is CredentialItem.Password -> item.value = passwordFinder.reqPassword(null)
                    else -> UnsupportedCredentialItem(uri, item.javaClass.name)
                }
            }
            return true
        }

        override fun supports(vararg items: CredentialItem) = items.all {
            it is CredentialItem.Username || it is CredentialItem.Password
        }
    }

    private fun withPasswordAuthentication(username: String, passwordFinder: InteractivePasswordFinder): GitOperation {
        val sessionFactory = SshjSessionFactory(username, SshAuthData.Password(passwordFinder), hostKeyFile)
        SshSessionFactory.setInstance(sessionFactory)
        this.provider = PasswordFinderCredentialsProvider(username, passwordFinder)
        return this
    }

    private fun withPublicKeyAuthentication(username: String, passphraseFinder: InteractivePasswordFinder): GitOperation {
        val sessionFactory = SshjSessionFactory(username, SshAuthData.PublicKeyFile(sshKeyFile, passphraseFinder), hostKeyFile)
        SshSessionFactory.setInstance(sessionFactory)
        this.provider = null
        return this
    }

    private fun withAndroidKeystoreAuthentication(username: String): GitOperation {
        val sessionFactory = SshjSessionFactory(username, SshAuthData.AndroidKeystoreKey(ANDROID_KEYSTORE_ALIAS_SSH_KEY), hostKeyFile)
        SshSessionFactory.setInstance(sessionFactory)
        this.provider = null
        return this
    }

    private fun withOpenKeychainAuthentication(username: String, identity: SshApiSessionFactory.ApiIdentity?): GitOperation {
        SshSessionFactory.setInstance(SshApiSessionFactory(username, identity))
        this.provider = null
        return this
    }

    private fun getSshKey(make: Boolean) {
        try {
            // Ask the UserPreference to provide us with the ssh-key
            // onResult has to be handled by the callingActivity
            val intent = Intent(callingActivity.applicationContext, UserPreference::class.java)
            intent.putExtra("operation", if (make) "make_ssh_key" else "get_ssh_key")
            callingActivity.startActivityForResult(intent, GET_SSH_KEY_FROM_CLONE)
        } catch (e: Exception) {
            println("Exception caught :(")
            e.printStackTrace()
        }
    }

    /**
     * Executes the GitCommand in an async task
     */
    abstract fun execute()

    private fun onMissingSshKeyFile() {
        MaterialAlertDialogBuilder(callingActivity).run {
            setMessage(callingActivity.resources.getString(R.string.ssh_preferences_dialog_text))
            setTitle(callingActivity.resources.getString(R.string.ssh_preferences_dialog_title))
            setPositiveButton(callingActivity.resources.getString(R.string.ssh_preferences_dialog_import)) { _, _ ->
                try {
                    // Ask the UserPreference to provide us with the ssh-key
                    // onResult has to be handled by the callingActivity
                    val intent = Intent(callingActivity.applicationContext, UserPreference::class.java)
                    intent.putExtra("operation", "get_ssh_key")
                    callingActivity.startActivityForResult(intent, GET_SSH_KEY_FROM_CLONE)
                } catch (e: Exception) {
                    println("Exception caught :(")
                    e.printStackTrace()
                }
            }
            setNegativeButton(callingActivity.resources.getString(R.string.ssh_preferences_dialog_generate)) { _, _ ->
                try {
                    // Duplicated code
                    val intent = Intent(callingActivity.applicationContext, UserPreference::class.java)
                    intent.putExtra("operation", "make_ssh_key")
                    callingActivity.startActivityForResult(intent, GET_SSH_KEY_FROM_CLONE)
                } catch (e: Exception) {
                    println("Exception caught :(")
                    e.printStackTrace()
                }
            }
            setNeutralButton(callingActivity.resources.getString(R.string.dialog_cancel)) { _, _ ->
                // Finish the blank GitActivity so user doesn't have to press back
                callingActivity.finish()
            }
            show()
        }
    }

    /**
     * Executes the GitCommand in an async task after creating the authentication
     *
     * @param connectionMode the server-connection mode
     * @param username the username
     * @param identity the api identity to use for auth in OpenKeychain connection mode
     */
    fun executeAfterAuthentication(
        connectionMode: ConnectionMode,
        username: String,
        identity: SshApiSessionFactory.ApiIdentity?
    ) {
        when (connectionMode) {
            ConnectionMode.SshKey -> when {
                !sshKeyFile.exists() -> {
                    MaterialAlertDialogBuilder(callingActivity)
                        .setMessage(R.string.ssh_preferences_dialog_text)
                        .setTitle(R.string.ssh_preferences_dialog_title)
                        .setPositiveButton(R.string.ssh_preferences_dialog_import) { _, _ ->
                            getSshKey(false)
                        }
                        .setNegativeButton(R.string.ssh_preferences_dialog_generate) { _, _ ->
                            getSshKey(true)
                        }
                        .setNeutralButton(R.string.dialog_cancel) { _, _ ->
                            // Finish the blank GitActivity so user doesn't have to press back
                            callingActivity.finish()
                        }.show()
                }
                sshKeyFile.readText() == "keystore" -> {
                    when (AndroidKeystoreKeyProvider.isUserAuthenticationRequired(ANDROID_KEYSTORE_ALIAS_SSH_KEY)) {
                        true -> BiometricAuthenticator.authenticate(callingActivity, R.string.biometric_prompt_title_ssh_auth) {
                            when (it) {
                                is BiometricAuthenticator.Result.Success -> {
                                    withAndroidKeystoreAuthentication(username).execute()
                                }
                                is BiometricAuthenticator.Result.Cancelled -> {
                                    callingActivity.finish()
                                }
                                is BiometricAuthenticator.Result.Failure -> {
                                    // Do nothing to allow retries.
                                }
                                else -> {
                                    // There is a chance we succeed if the user recently confirmed
                                    // their screen lock. Doing so would have a potential to confuse
                                    // users though, who might deduce that the screen lock
                                    // protection is not effective. Hence, we fail with an error.
                                    Toast.makeText(callingActivity.applicationContext, R.string.biometric_auth_generic_failure, Toast.LENGTH_LONG).show()
                                    callingActivity.finish()
                                }
                            }
                        }
                        false -> withAndroidKeystoreAuthentication(username).execute()
                        else -> {
                            // The key is no longer available or has been invalidated by screen lock
                            // deactivation.
                            sshKeyFile.delete()
                            onMissingSshKeyFile()
                        }
                    }
                }
                else -> withPublicKeyAuthentication(username, GitOperationCredentialFinder(
                    callingActivity, connectionMode)).execute()
            }
            ConnectionMode.OpenKeychain -> withOpenKeychainAuthentication(username, identity).execute()
            ConnectionMode.Password -> withPasswordAuthentication(
                username, GitOperationCredentialFinder(callingActivity, connectionMode)).execute()
            ConnectionMode.None -> execute()
        }
    }

    /**
     * Action to execute on error
     */
    open fun onError(err: Exception) {
        // Clear various auth related fields on failure
        when (SshSessionFactory.getInstance()) {
            is SshApiSessionFactory -> {
                PreferenceManager.getDefaultSharedPreferences(callingActivity.applicationContext)
                    .edit { remove(PreferenceKeys.SSH_OPENKEYSTORE_KEYID) }
            }
            is SshjSessionFactory -> {
                callingActivity.applicationContext
                    .getEncryptedPrefs("git_operation")
                    .edit {
                        remove(PreferenceKeys.SSH_KEY_LOCAL_PASSPHRASE)
                        remove(PreferenceKeys.HTTPS_PASSWORD)
                    }
            }
        }
    }

    /**
     * Action to execute on success
     */
    open fun onSuccess() {}

    companion object {

        const val GET_SSH_KEY_FROM_CLONE = 201
    }
}
