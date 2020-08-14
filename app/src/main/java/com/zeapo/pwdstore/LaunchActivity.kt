/*
 * Copyright © 2014-2020 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package com.zeapo.pwdstore

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import androidx.appcompat.app.AppCompatActivity
import com.zeapo.pwdstore.crypto.DecryptActivity

class LaunchActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (intent.action == ACTION_DECRYPT_PASS) {
            val decryptIntent = Intent(this, DecryptActivity::class.java)
            decryptIntent.putExtra("NAME", intent.getStringExtra("NAME"))
            decryptIntent.putExtra("FILE_PATH", intent.getStringExtra("FILE_PATH"))
            decryptIntent.putExtra("REPO_PATH", intent.getStringExtra("REPO_PATH"))
            decryptIntent.putExtra("LAST_CHANGED_TIMESTAMP", intent.getLongExtra("LAST_CHANGED_TIMESTAMP", 0L))
            startActivity(decryptIntent)
        } else {
            startActivity(Intent(this, PasswordStore::class.java))
        }
        finish()
    }

    companion object {

        const val ACTION_DECRYPT_PASS = "DECRYPT_PASS"
    }
}
