/*
 * Copyright © 2014-2020 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package com.zeapo.pwdstore

object AuthManager {

    private var isAuthRequired = true

    /**
     * Whether or not the user has requested for the app to be locked behind a biometric
     * authentication prompt.
     */
    var isAuthEnabled = false

    /**
     * Signal that the next biometric authentication request should be skipped. This is used to
     * make OpenKeychain actions that require user interaction work seamlessly without prompting
     * the user for biometric authentication.
     */
    var skipNextAuthRequest = false

    /**
     * Called when app goes into the background to reset fields
     */
    fun onBackground() {
        if (skipNextAuthRequest) {
            isAuthRequired = false
            skipNextAuthRequest = false
        } else {
            isAuthRequired = true
        }
    }

    /**
     * Reset fields on authentication success
     */
    fun onSuccess() {
        skipNextAuthRequest = false
        isAuthRequired = false
    }

    /**
     * Reset fields on authentication failure
     */
    fun onFailure() {
        skipNextAuthRequest = false
        isAuthRequired = true
    }

    /**
     * Notifies [BaseActivity] whether or not to start an authentication request
     */
    fun shouldAuthenticate(): Boolean {
        return isAuthEnabled && isAuthRequired && !skipNextAuthRequest
    }
}
