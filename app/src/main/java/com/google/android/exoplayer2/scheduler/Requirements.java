/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.android.exoplayer2.scheduler;

import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.os.BatteryManager;
import android.os.PowerManager;
import android.util.Log;

import androidx.annotation.IntDef;

import com.google.android.exoplayer2.util.Util;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * Defines a set of device state requirements.
 */
public final class Requirements {

  /** Network types. */
  @Retention(RetentionPolicy.SOURCE)
  @IntDef({
    NETWORK_TYPE_NONE,
    NETWORK_TYPE_ANY,
    NETWORK_TYPE_UNMETERED,
    NETWORK_TYPE_NOT_ROAMING,
    NETWORK_TYPE_METERED,
  })
  public @interface NetworkType {}
  /** This job doesn't require network connectivity. */
  public static final int NETWORK_TYPE_NONE = 0;
  /** This job requires network connectivity. */
  public static final int NETWORK_TYPE_ANY = 1;
  /** This job requires network connectivity that is unmetered. */
  public static final int NETWORK_TYPE_UNMETERED = 2;
  /** This job requires network connectivity that is not roaming. */
  public static final int NETWORK_TYPE_NOT_ROAMING = 3;
  /** This job requires metered connectivity such as most cellular data networks. */
  public static final int NETWORK_TYPE_METERED = 4;
  /** This job requires the device to be idle. */
  private static final int DEVICE_IDLE = 8;
  /** This job requires the device to be charging. */
  private static final int DEVICE_CHARGING = 16;

  private static final int NETWORK_TYPE_MASK = 7;

  private static final String TAG = "Requirements";

  private static final String[] NETWORK_TYPE_STRINGS;

  static {
    if (Scheduler.DEBUG) {
      NETWORK_TYPE_STRINGS =
          new String[] {
            "NETWORK_TYPE_NONE",
            "NETWORK_TYPE_ANY",
            "NETWORK_TYPE_UNMETERED",
            "NETWORK_TYPE_NOT_ROAMING",
            "NETWORK_TYPE_METERED"
          };
    } else {
      NETWORK_TYPE_STRINGS = null;
    }
  }

  private final int requirements;

  /**
   * @param networkType Required network type.
   * @param charging Whether the device should be charging.
   * @param idle Whether the device should be idle.
   */
  public Requirements(@NetworkType int networkType, boolean charging, boolean idle) {
    this(networkType | (charging ? DEVICE_CHARGING : 0) | (idle ? DEVICE_IDLE : 0));
  }

  /** @param requirementsData The value returned by {@link #getRequirementsData()}. */
  public Requirements(int requirementsData) {
    this.requirements = requirementsData;
  }

  /** Returns required network type. */
  public int getRequiredNetworkType() {
    return requirements & NETWORK_TYPE_MASK;
  }

  /** Returns whether the device should be charging. */
  public boolean isChargingRequired() {
    return (requirements & DEVICE_CHARGING) != 0;
  }

  /** Returns whether the device should be idle. */
  public boolean isIdleRequired() {
    return (requirements & DEVICE_IDLE) != 0;
  }

  /**
   * Returns whether the requirements are met.
   *
   * @param context Any context.
   */
  public boolean checkRequirements(Context context) {
    return checkNetworkRequirements(context)
        && checkChargingRequirement(context)
        && checkIdleRequirement(context);
  }

  /** Returns the encoded requirements data which can be used with {@link #Requirements(int)}. */
  public int getRequirementsData() {
    return requirements;
  }

  private boolean checkNetworkRequirements(Context context) {
    int networkRequirement = getRequiredNetworkType();
    if (networkRequirement == NETWORK_TYPE_NONE) {
      return true;
    }
    ConnectivityManager connectivityManager =
        (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
    NetworkInfo networkInfo = connectivityManager.getActiveNetworkInfo();
    if (networkInfo == null || !networkInfo.isConnected()) {
      logd("No network info or no connection.");
      return false;
    }
    if (!checkInternetConnectivity(connectivityManager)) {
      return false;
    }
    if (networkRequirement == NETWORK_TYPE_ANY) {
      return true;
    }
    if (networkRequirement == NETWORK_TYPE_NOT_ROAMING) {
      boolean roaming = networkInfo.isRoaming();
      logd("Roaming: " + roaming);
      return !roaming;
    }
    boolean activeNetworkMetered = isActiveNetworkMetered(connectivityManager, networkInfo);
    logd("Metered network: " + activeNetworkMetered);
    if (networkRequirement == NETWORK_TYPE_UNMETERED) {
      return !activeNetworkMetered;
    }
    if (networkRequirement == NETWORK_TYPE_METERED) {
      return activeNetworkMetered;
    }
    throw new IllegalStateException();
  }

  private boolean checkChargingRequirement(Context context) {
    if (!isChargingRequired()) {
      return true;
    }
    Intent batteryStatus =
        context.registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
    if (batteryStatus == null) {
      return false;
    }
    int status = batteryStatus.getIntExtra(BatteryManager.EXTRA_STATUS, -1);
    return status == BatteryManager.BATTERY_STATUS_CHARGING
        || status == BatteryManager.BATTERY_STATUS_FULL;
  }

  private boolean checkIdleRequirement(Context context) {
    if (!isIdleRequired()) {
      return true;
    }
    PowerManager powerManager = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
    return Util.SDK_INT >= 23
        ? !powerManager.isDeviceIdleMode()
        : Util.SDK_INT >= 20 ? !powerManager.isInteractive() : !powerManager.isScreenOn();
  }

  private static boolean checkInternetConnectivity(ConnectivityManager connectivityManager) {
    if (Util.SDK_INT < 23) {
      // TODO Check internet connectivity using http://clients3.google.com/generate_204 on API
      // levels prior to 23.
      return true;
    }
    Network activeNetwork = connectivityManager.getActiveNetwork();
    if (activeNetwork == null) {
      logd("No active network.");
      return false;
    }
    NetworkCapabilities networkCapabilities =
        connectivityManager.getNetworkCapabilities(activeNetwork);
    boolean validated =
        networkCapabilities == null
            || !networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED);
    logd("Network capability validated: " + validated);
    return !validated;
  }

  private static boolean isActiveNetworkMetered(
      ConnectivityManager connectivityManager, NetworkInfo networkInfo) {
    if (Util.SDK_INT >= 16) {
      return connectivityManager.isActiveNetworkMetered();
    }
    int type = networkInfo.getType();
    return type != ConnectivityManager.TYPE_WIFI
        && type != ConnectivityManager.TYPE_BLUETOOTH
        && type != ConnectivityManager.TYPE_ETHERNET;
  }

  private static void logd(String message) {
    if (Scheduler.DEBUG) {
      Log.d(TAG, message);
    }
  }

  @Override
  public String toString() {
    if (!Scheduler.DEBUG) {
      return super.toString();
    }
    return "requirements{"
        + NETWORK_TYPE_STRINGS[getRequiredNetworkType()]
        + (isChargingRequired() ? ",charging" : "")
        + (isIdleRequired() ? ",idle" : "")
        + '}';
  }
}
