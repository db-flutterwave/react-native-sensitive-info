package dev.mcodex;

import android.content.Context
import android.content.SharedPreferences
import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import android.os.CancellationSignal
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.annotation.NonNull
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricPrompt.PromptInfo
import androidx.fragment.app.FragmentActivity
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.UiThreadUtil
import com.facebook.react.bridge.WritableMap
import com.facebook.react.bridge.WritableNativeMap
import com.facebook.react.modules.core.DeviceEventManagerModule.RCTDeviceEventEmitter
import dev.mcodex.utils.AppConstants
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.math.BigInteger
import java.security.InvalidKeyException
import java.security.Key
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.UnrecoverableKeyException
import java.util.Calendar
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.IllegalBlockSizeException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.security.auth.x500.X500Principal

class RNSensitiveInfoModule(reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    private var mFingerprintManager: FingerprintManager? = null
    private var mKeyStore: KeyStore? = null
    private var mCancellationSignal: CancellationSignal? = null

    // Keep it true by default to maintain backwards compatibility with existing users.
    private var invalidateEnrollment = true

    init {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN_MR2) {
            val cause: Exception = RuntimeException("Keystore is not supported!")
            throw RuntimeException("Android version is too low", cause)
        }
        try {
            mKeyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER)
            mKeyStore?.load(null)
        } catch (e: Exception) {
            e.printStackTrace()
        }
        initKeyStore()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                mFingerprintManager =
                    reactContext.getSystemService(Context.FINGERPRINT_SERVICE) as FingerprintManager
                initFingerprintKeyStore()
            } catch (e: Exception) {
                Log.d("RNSensitiveInfo", "Fingerprint not supported")
            }
        }
    }

    override fun getName(): String {
        return "RNSensitiveInfo"
    }

    /**
     * Checks whether the device supports Biometric authentication and if the user has
     * enrolled at least one credential.
     *
     * @return true if the user has a biometric capable device and has enrolled
     * one or more credentials
     */
    /**
     * Checks whether the device supports Biometric authentication and if the user has
     * enrolled at least one credential.
     *
     * @return true if the user has a biometric capable device and has enrolled
     * one or more credentials
     */
    private fun hasSetupBiometricCredential(): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val reactApplicationContext = reactApplicationContext
                val biometricManager = BiometricManager.from(reactApplicationContext)
                val canAuthenticate = biometricManager.canAuthenticate()
                canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS
            } else {
                false
            }
        } catch (e: Exception) {
            false
        }
    }

    @ReactMethod
    fun setInvalidatedByBiometricEnrollment(
        invalidatedByBiometricEnrollment: Boolean,
        pm: Promise
    ) {
        invalidateEnrollment = invalidatedByBiometricEnrollment
        try {
            prepareKey()
        } catch (e: Exception) {
            pm.reject(e)
        }
    }

    // @ReactMethod
    // public void isHardwareDetected(final Promise pm) {
    //     if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
    //         ReactApplicationContext reactApplicationContext = getReactApplicationContext();
    //         BiometricManager biometricManager = BiometricManager.from(reactApplicationContext);
    //         int canAuthenticate = biometricManager.canAuthenticate();

    //         pm.resolve(canAuthenticate != BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE);
    //     } else {
    //         pm.resolve(false);
    //     }
    // }

    @ReactMethod
    fun hasEnrolledFingerprints(pm: Promise) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && mFingerprintManager != null) {
            pm.resolve(mFingerprintManager!!.hasEnrolledFingerprints())
        } else {
            pm.resolve(false)
        }
    }

    @ReactMethod
    fun isSensorAvailable(promise: Promise) {
        promise.resolve(hasSetupBiometricCredential())
    }

    @ReactMethod
    fun getItem(key: String?, options: ReadableMap, pm: Promise) {
        val name = sharedPreferences(options)
        val value = prefs(name).getString(key, null)
        if (value != null && options.hasKey("touchID") && options.getBoolean("touchID")) {
            val showModal = options.hasKey("showModal") && options.getBoolean("showModal")
            val strings: HashMap<*, *> = if (options.hasKey("strings")) options.getMap("strings")!!
                .toHashMap() else HashMap<Any?, Any?>()
            decryptWithAes(value, showModal, strings, pm, null)
        } else if (value != null) {
            try {
                pm.resolve(decrypt(value))
            } catch (e: Exception) {
                pm.reject(e)
            }
        } else {
            pm.resolve(value)
        }
    }

    @ReactMethod
    fun hasItem(key: String?, options: ReadableMap, pm: Promise) {
        val name = sharedPreferences(options)
        val value = prefs(name).getString(key, null)
        pm.resolve(if (value != null) true else false)
    }

    @ReactMethod
    fun setItem(key: String, value: String, options: ReadableMap, pm: Promise) {
        val name = sharedPreferences(options)
        if (options.hasKey("touchID") && options.getBoolean("touchID")) {
            val showModal = options.hasKey("showModal") && options.getBoolean("showModal")
            val strings: HashMap<*, *> = if (options.hasKey("strings")) options.getMap("strings")!!
                .toHashMap() else HashMap<Any?, Any?>()
            putExtraWithAES(key, value, prefs(name), showModal, strings, pm, null)
        } else {
            try {
                putExtra(key, encrypt(value), prefs(name))
                pm.resolve(value)
            } catch (e: Exception) {
                e.printStackTrace()
                pm.reject(e)
            }
        }
    }


    @ReactMethod
    fun deleteItem(key: String, options: ReadableMap, pm: Promise) {
        val name = sharedPreferences(options)
        val editor = prefs(name).edit()
        val wasRemoved = editor.remove(key).commit()
        if (!wasRemoved) {
            pm.reject(Exception("Could not remove $key from Shared Preferences"))
        } else {
            pm.resolve(null)
        }
    }


    @ReactMethod
    fun getAllItems(options: ReadableMap, pm: Promise) {
        val name = sharedPreferences(options)
        val allEntries = prefs(name).all
        val resultData: WritableMap = WritableNativeMap()
        for ((key, value1) in allEntries) {
            var value: String = value1.toString()
            try {
                value = decrypt(value)
            } catch (e: Exception) {
                Log.d("RNSensitiveInfo", Log.getStackTraceString(e))
            }
            resultData.putString(key!!, value)
        }
        pm.resolve(resultData)
    }

    @ReactMethod
    fun cancelFingerprintAuth() {
        if (mCancellationSignal != null && !mCancellationSignal!!.isCanceled) {
            mCancellationSignal!!.cancel()
        }
    }

    private fun prefs(name: String): SharedPreferences {
        return reactApplicationContext.getSharedPreferences(name, Context.MODE_PRIVATE)
    }

    @NonNull
    private fun sharedPreferences(options: ReadableMap): String {
        var name =
            if (options.hasKey("sharedPreferencesName")) options.getString("sharedPreferencesName") else "shared_preferences"
        if (name == null) {
            name = "shared_preferences"
        }
        return name
    }


    @Throws(Exception::class)
    private fun putExtra(key: String, value: String, mSharedPreferences: SharedPreferences) {
        val editor = mSharedPreferences.edit()
        val wasWritten = editor.putString(key, value).commit()
        if (!wasWritten) {
            throw Exception("Could not write $key to Shared Preferences")
        }
    }

    /**
     * Generates a new RSA key and stores it under the { @code KEY_ALIAS } in the
     * Android Keystore.
     */
    private fun initKeyStore() {
        try {
            if (!mKeyStore!!.containsAlias(KEY_ALIAS)) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    val keyGenerator = KeyGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_AES,
                        ANDROID_KEYSTORE_PROVIDER
                    )
                    keyGenerator.init(
                        KeyGenParameterSpec.Builder(
                            KEY_ALIAS,
                            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                        )
                            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                            .setRandomizedEncryptionRequired(false)
                            .build()
                    )
                    keyGenerator.generateKey()
                } else {
                    val notBefore = Calendar.getInstance()
                    val notAfter = Calendar.getInstance()
                    notAfter.add(Calendar.YEAR, 10)
                    val spec = KeyPairGeneratorSpec.Builder(
                        reactApplicationContext
                    )
                        .setAlias(KEY_ALIAS)
                        .setSubject(X500Principal("CN=" + KEY_ALIAS))
                        .setSerialNumber(BigInteger.valueOf(1337))
                        .setStartDate(notBefore.time)
                        .setEndDate(notAfter.time)
                        .build()
                    val kpGenerator = KeyPairGenerator.getInstance("RSA", ANDROID_KEYSTORE_PROVIDER)
                    kpGenerator.initialize(spec)
                    kpGenerator.generateKeyPair()
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun showDialog(
        strings: HashMap<*, *>,
        cryptoObject: BiometricPrompt.CryptoObject,
        callback: BiometricPrompt.AuthenticationCallback
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            UiThreadUtil.runOnUiThread(
                Runnable {
                    try {
                        val activity = currentActivity
                        if (activity == null) {
                            callback.onAuthenticationError(
                                BiometricPrompt.ERROR_CANCELED,
                                if (strings.containsKey("cancelled")) strings["cancelled"].toString() else "Authentication was cancelled"
                            )
                            return@Runnable
                        }
                        val fragmentActivity = currentActivity as FragmentActivity?
                        val executor: Executor = Executors.newSingleThreadExecutor()
                        val biometricPrompt = BiometricPrompt(
                            fragmentActivity!!, executor, callback
                        )
                        val promptInfo = PromptInfo.Builder()
                            .setDeviceCredentialAllowed(false)
                            .setNegativeButtonText(if (strings.containsKey("cancel")) strings["cancel"].toString() else "Cancel")
                            .setDescription(if (strings.containsKey("description")) strings["description"].toString() else null)
                            .setTitle(if (strings.containsKey("header")) strings["header"].toString() else "Unlock with your fingerprint")
                            .build()
                        biometricPrompt.authenticate(promptInfo, cryptoObject)
                    } catch (e: Exception) {
                        throw e
                    }
                }
            )
        }
    }

    /**
     * Generates a new AES key and stores it under the { @code KEY_ALIAS_AES } in the
     * Android Keystore.
     */
    private fun initFingerprintKeyStore() {
        try {
            // Check if a generated key exists under the KEY_ALIAS_AES .
            if (!mKeyStore!!.containsAlias(KEY_ALIAS_AES)) {
                prepareKey()
            }
        } catch (e: Exception) {
            //
        }
    }

    @Throws(Exception::class)
    private fun prepareKey() {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE_PROVIDER
        )
        var builder: KeyGenParameterSpec.Builder? = null
        builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS_AES,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
        builder.setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            .setKeySize(256)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7) // forces user authentication with fingerprint
            .setUserAuthenticationRequired(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            try {
                builder.setInvalidatedByBiometricEnrollment(invalidateEnrollment)
            } catch (e: Exception) {
                Log.d(
                    "RNSensitiveInfo",
                    "Error setting setInvalidatedByBiometricEnrollment: " + e.message
                )
            }
        }
        keyGenerator.init(builder.build())
        keyGenerator.generateKey()
    }

    private fun putExtraWithAES(
        key: String,
        value: String,
        mSharedPreferences: SharedPreferences,
        showModal: Boolean,
        strings: HashMap<*, *>,
        pm: Promise,
        cipher: Cipher?
    ) {
        var cipher = cipher
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && hasSetupBiometricCredential()) {
            try {
                if (cipher == null) {
                    val secretKey = mKeyStore!!.getKey(KEY_ALIAS_AES, null) as SecretKey
                    cipher = Cipher.getInstance(AES_DEFAULT_TRANSFORMATION)
                    cipher.init(Cipher.ENCRYPT_MODE, secretKey)

                    // Retrieve information about the SecretKey from the KeyStore.
                    val factory = SecretKeyFactory.getInstance(
                        secretKey.algorithm, ANDROID_KEYSTORE_PROVIDER
                    )
                    val info = factory.getKeySpec(
                        secretKey,
                        KeyInfo::class.java
                    ) as KeyInfo
                    if (info.isUserAuthenticationRequired &&
                        info.userAuthenticationValidityDurationSeconds <= 0
                    ) {
                        if (showModal) {
                            class PutExtraWithAESCallback :
                                BiometricPrompt.AuthenticationCallback() {
                                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                                        putExtraWithAES(
                                            key,
                                            value,
                                            mSharedPreferences,
                                            true,
                                            strings,
                                            pm,
                                            result.cryptoObject!!
                                                .cipher
                                        )
                                    }
                                }

                                override fun onAuthenticationError(
                                    errorCode: Int,
                                    errString: CharSequence
                                ) {
                                    pm.reject(errorCode.toString(), errString.toString())
                                }

                                override fun onAuthenticationFailed() {
                                    reactApplicationContext.getJSModule<RCTDeviceEventEmitter>(
                                        RCTDeviceEventEmitter::class.java
                                    )
                                        .emit(
                                            AppConstants.E_AUTHENTICATION_NOT_RECOGNIZED,
                                            "Authentication not recognized."
                                        )
                                }
                            }
                            showDialog(
                                strings,
                                BiometricPrompt.CryptoObject(cipher),
                                PutExtraWithAESCallback()
                            )
                        } else {
                            mCancellationSignal = CancellationSignal()
                            mFingerprintManager!!.authenticate(FingerprintManager.CryptoObject(
                                cipher
                            ), mCancellationSignal,
                                0, object : FingerprintManager.AuthenticationCallback() {
                                    override fun onAuthenticationFailed() {
                                        super.onAuthenticationFailed()
                                        reactApplicationContext.getJSModule<RCTDeviceEventEmitter>(
                                            RCTDeviceEventEmitter::class.java
                                        )
                                            .emit(
                                                AppConstants.E_AUTHENTICATION_NOT_RECOGNIZED,
                                                "Fingerprint not recognized."
                                            )
                                    }

                                    override fun onAuthenticationError(
                                        errorCode: Int,
                                        errString: CharSequence
                                    ) {
                                        super.onAuthenticationError(errorCode, errString)
                                        pm.reject(errorCode.toString(), errString.toString())
                                    }

                                    override fun onAuthenticationHelp(
                                        helpCode: Int,
                                        helpString: CharSequence
                                    ) {
                                        super.onAuthenticationHelp(helpCode, helpString)
                                        reactApplicationContext.getJSModule<RCTDeviceEventEmitter>(
                                            RCTDeviceEventEmitter::class.java
                                        )
                                            .emit(
                                                AppConstants.FINGERPRINT_AUTHENTICATION_HELP,
                                                helpString.toString()
                                            )
                                    }

                                    override fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult) {
                                        super.onAuthenticationSucceeded(result)
                                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                                            putExtraWithAES(
                                                key,
                                                value,
                                                mSharedPreferences,
                                                false,
                                                strings,
                                                pm,
                                                result.cryptoObject.cipher
                                            )
                                        }
                                    }
                                }, null
                            )
                        }
                    }
                    return
                }
                val encryptedBytes = cipher.doFinal(value.toByteArray())

                // Encode the initialization vector (IV) and encryptedBytes to Base64.
                val base64IV = Base64.encodeToString(cipher.iv, Base64.DEFAULT)
                val base64Cipher = Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
                val result = base64IV + DELIMITER + base64Cipher
                try {
                    putExtra(key, result, mSharedPreferences)
                    pm.resolve(value)
                } catch (e: Exception) {
                    pm.reject(e)
                }
            } catch (e: InvalidKeyException) {
                try {
                    mKeyStore!!.deleteEntry(KEY_ALIAS_AES)
                    prepareKey()
                } catch (keyResetError: Exception) {
                    pm.reject(keyResetError)
                }
                pm.reject(e)
            } catch (e: UnrecoverableKeyException) {
                try {
                    mKeyStore!!.deleteEntry(KEY_ALIAS_AES)
                    prepareKey()
                } catch (keyResetError: Exception) {
                    pm.reject(keyResetError)
                }
                pm.reject(e)
            } catch (e: IllegalBlockSizeException) {
                if (e.cause != null && e.cause!!.message!!.contains("Key user not authenticated")) {
                    try {
                        mKeyStore!!.deleteEntry(KEY_ALIAS_AES)
                        prepareKey()
                        pm.reject(
                            AppConstants.KM_ERROR_KEY_USER_NOT_AUTHENTICATED,
                            e.cause!!.message
                        )
                    } catch (keyResetError: Exception) {
                        pm.reject(keyResetError)
                    }
                } else {
                    pm.reject(e)
                }
            } catch (e: SecurityException) {
                pm.reject(e)
            } catch (e: Exception) {
                pm.reject(e)
            }
        } else {
            pm.reject(AppConstants.E_BIOMETRIC_NOT_SUPPORTED, "Biometrics not supported")
        }
    }

    private fun decryptWithAes(
        encrypted: String,
        showModal: Boolean,
        strings: HashMap<*, *>,
        pm: Promise,
        cipher: Cipher?
    ) {
        var cipher = cipher
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
            && hasSetupBiometricCredential()
        ) {
            val inputs = encrypted.split(DELIMITER.toRegex()).dropLastWhile { it.isEmpty() }
                .toTypedArray()
            if (inputs.size < 2) {
                pm.reject("DecryptionFailed", "DecryptionFailed")
            }
            try {
                val iv = Base64.decode(inputs[0], Base64.DEFAULT)
                val cipherBytes = Base64.decode(inputs[1], Base64.DEFAULT)
                if (cipher == null) {
                    val secretKey = mKeyStore!!.getKey(KEY_ALIAS_AES, null) as SecretKey
                    cipher = Cipher.getInstance(AES_DEFAULT_TRANSFORMATION)
                    cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))
                    val factory = SecretKeyFactory.getInstance(
                        secretKey.algorithm, ANDROID_KEYSTORE_PROVIDER
                    )
                    val info = factory.getKeySpec(
                        secretKey,
                        KeyInfo::class.java
                    ) as KeyInfo
                    if (info.isUserAuthenticationRequired &&
                        info.userAuthenticationValidityDurationSeconds <= 0
                    ) {
                        if (showModal) {
                            class DecryptWithAesCallback :
                                BiometricPrompt.AuthenticationCallback() {
                                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                                        decryptWithAes(
                                            encrypted, true, strings, pm, result.cryptoObject!!
                                                .cipher
                                        )
                                    }
                                }

                                override fun onAuthenticationError(
                                    errorCode: Int,
                                    errString: CharSequence
                                ) {
                                    pm.reject(errorCode.toString(), errString.toString())
                                }

                                override fun onAuthenticationFailed() {
                                    reactApplicationContext.getJSModule<RCTDeviceEventEmitter>(
                                        RCTDeviceEventEmitter::class.java
                                    )
                                        .emit(
                                            AppConstants.E_AUTHENTICATION_NOT_RECOGNIZED,
                                            "Authentication not recognized."
                                        )
                                }
                            }
                            showDialog(
                                strings,
                                BiometricPrompt.CryptoObject(cipher),
                                DecryptWithAesCallback()
                            )
                        } else {
                            mCancellationSignal = CancellationSignal()
                            mFingerprintManager!!.authenticate(FingerprintManager.CryptoObject(
                                cipher
                            ), mCancellationSignal,
                                0, object : FingerprintManager.AuthenticationCallback() {
                                    override fun onAuthenticationFailed() {
                                        super.onAuthenticationFailed()
                                        reactApplicationContext.getJSModule<RCTDeviceEventEmitter>(
                                            RCTDeviceEventEmitter::class.java
                                        )
                                            .emit(
                                                AppConstants.E_AUTHENTICATION_NOT_RECOGNIZED,
                                                "Fingerprint not recognized."
                                            )
                                    }

                                    override fun onAuthenticationError(
                                        errorCode: Int,
                                        errString: CharSequence
                                    ) {
                                        super.onAuthenticationError(errorCode, errString)
                                        pm.reject(errorCode.toString(), errString.toString())
                                    }

                                    override fun onAuthenticationHelp(
                                        helpCode: Int,
                                        helpString: CharSequence
                                    ) {
                                        super.onAuthenticationHelp(helpCode, helpString)
                                        reactApplicationContext.getJSModule<RCTDeviceEventEmitter>(
                                            RCTDeviceEventEmitter::class.java
                                        )
                                            .emit(
                                                AppConstants.FINGERPRINT_AUTHENTICATION_HELP,
                                                helpString.toString()
                                            )
                                    }

                                    override fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult) {
                                        super.onAuthenticationSucceeded(result)
                                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                                            decryptWithAes(
                                                encrypted,
                                                false,
                                                strings,
                                                pm,
                                                result.cryptoObject.cipher
                                            )
                                        }
                                    }
                                }, null
                            )
                        }
                    }
                    return
                }
                val decryptedBytes = cipher.doFinal(cipherBytes)
                pm.resolve(String(decryptedBytes))
            } catch (e: InvalidKeyException) {
                try {
                    mKeyStore!!.deleteEntry(KEY_ALIAS_AES)
                    prepareKey()
                } catch (keyResetError: Exception) {
                    pm.reject(keyResetError)
                }
                pm.reject(e)
            } catch (e: UnrecoverableKeyException) {
                try {
                    mKeyStore!!.deleteEntry(KEY_ALIAS_AES)
                    prepareKey()
                } catch (keyResetError: Exception) {
                    pm.reject(keyResetError)
                }
                pm.reject(e)
            } catch (e: IllegalBlockSizeException) {
                if (e.cause != null && e.cause!!.message!!.contains("Key user not authenticated")) {
                    try {
                        mKeyStore!!.deleteEntry(KEY_ALIAS_AES)
                        prepareKey()
                        pm.reject(
                            AppConstants.KM_ERROR_KEY_USER_NOT_AUTHENTICATED,
                            e.cause!!.message
                        )
                    } catch (keyResetError: Exception) {
                        pm.reject(keyResetError)
                    }
                } else {
                    pm.reject(e)
                }
            } catch (e: BadPaddingException) {
                Log.d("RNSensitiveInfo", "Biometric key invalid")
                pm.reject(AppConstants.E_BIOMETRICS_INVALIDATED, e.cause!!.message)
            } catch (e: SecurityException) {
                pm.reject(e)
            } catch (e: Exception) {
                pm.reject(e)
            }
        } else {
            pm.reject(AppConstants.E_BIOMETRIC_NOT_SUPPORTED, "Biometrics not supported")
        }
    }

    @Throws(Exception::class)
    fun encrypt(input: String): String {
        val bytes = input.toByteArray()
        val c: Cipher
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val secretKey: Key = (mKeyStore!!.getEntry(
                KEY_ALIAS,
                null
            ) as KeyStore.SecretKeyEntry).secretKey
            c = Cipher.getInstance(AES_GCM)
            c.init(
                Cipher.ENCRYPT_MODE,
                secretKey,
                GCMParameterSpec(128, FIXED_IV)
            )
        } else {
            val publicKey = (mKeyStore!!.getEntry(
                KEY_ALIAS,
                null
            ) as KeyStore.PrivateKeyEntry).certificate.publicKey
            c = Cipher.getInstance(RSA_ECB)
            c.init(Cipher.ENCRYPT_MODE, publicKey)
        }
        var cipherTextSize = 0
        val byteStream = ByteArrayOutputStream()
        val dataStream = DataOutputStream(byteStream)
        val plaintextStream = ByteArrayInputStream(bytes)
        val chunkSize = 4 * 1024
        val buffer = ByteArray(chunkSize)
        while (plaintextStream.available() > chunkSize) {
            val readBytes = plaintextStream.read(buffer)
            val ciphertextChunk = c.update(buffer, 0, readBytes)
            cipherTextSize += ciphertextChunk.size
            dataStream.write(ciphertextChunk)
        }
        val readBytes = plaintextStream.read(buffer)
        val ciphertextChunk = c.doFinal(buffer, 0, readBytes)
        cipherTextSize += ciphertextChunk.size
        dataStream.write(ciphertextChunk)
        return Base64.encodeToString(byteStream.toByteArray(), Base64.NO_WRAP)
    }


    @Throws(Exception::class)
    fun decrypt(encrypted: String?): String {
        if (encrypted == null) {
            val cause: Exception = RuntimeException("Invalid argument at decrypt function")
            throw RuntimeException("encrypted argument can't be null", cause)
        }
        val c: Cipher
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val secretKey: Key =
                (mKeyStore!!.getEntry(KEY_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
            c = Cipher.getInstance(AES_GCM)
            c.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, FIXED_IV))
        } else {
            val privateKey =
                (mKeyStore!!.getEntry(KEY_ALIAS, null) as KeyStore.PrivateKeyEntry).privateKey
            c = Cipher.getInstance(RSA_ECB)
            c.init(Cipher.DECRYPT_MODE, privateKey)
        }
        val bytes = Base64.decode(encrypted, Base64.NO_WRAP)
        val byteStream = ByteArrayInputStream(bytes)
        val dataStream = DataInputStream(byteStream)
        val cipherStream = CipherInputStream(byteStream, c)
        val outputStream = ByteArrayOutputStream()
        val buffer = ByteArray(1024)
        var len: Int
        while (cipherStream.read(buffer).also { len = it } != -1) {
            outputStream.write(buffer, 0, len)
        }
        val decodedBytes = outputStream.toByteArray()
        return String(decodedBytes)
    }

    companion object {
        // This must have 'AndroidKeyStore' as value. Unfortunately there is no predefined constant.
        private const val ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore"

        // This is the default transformation used throughout this sample project.
        private const val AES_DEFAULT_TRANSFORMATION = KeyProperties.KEY_ALGORITHM_AES + "/" +
                KeyProperties.BLOCK_MODE_CBC + "/" +
                KeyProperties.ENCRYPTION_PADDING_PKCS7
        private const val AES_GCM = "AES/GCM/NoPadding"
        private const val RSA_ECB = "RSA/ECB/PKCS1Padding"
        private const val DELIMITER = "]"
        private val FIXED_IV = byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1)
        private const val KEY_ALIAS = "MySharedPreferenceKeyAlias"
        private const val KEY_ALIAS_AES = "MyAesKeyAlias"
    }
}
