// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.support_lib_glue;

import static org.chromium.support_lib_glue.SupportLibWebViewChromiumFactory.recordApiCall;
import static org.chromium.support_lib_glue.SupportLibWebViewChromiumFactory.recordWebViewApiCall;
import static org.chromium.support_lib_glue.SupportLibWebViewChromiumFactory.convertToParameterArray;

import android.webkit.WebSettings;

import org.chromium.android_webview.AwDarkMode;
import org.chromium.android_webview.AwSettings;
import org.chromium.base.Log;
import org.chromium.base.TraceEvent;
import org.chromium.support_lib_boundary.WebSettingsBoundaryInterface;
import org.chromium.support_lib_glue.SupportLibWebViewChromiumFactory.ApiCall;

import java.util.Map;
import java.util.Set;

/**
 * Adapter between WebSettingsBoundaryInterface and AwSettings.
 */
class SupportLibWebSettingsAdapter implements WebSettingsBoundaryInterface {
    private static final String TAG = "SupportWebSettings";
    private final AwSettings mAwSettings;

    public SupportLibWebSettingsAdapter(AwSettings awSettings) {
        mAwSettings = awSettings;
    }

    @Override
    public void setOffscreenPreRaster(boolean enabled) {
        try (TraceEvent event = TraceEvent.scoped(
                     "WebView.APICall.AndroidX.WEB_SETTINGS_SET_OFFSCREEN_PRE_RASTER")) {
            recordWebViewApiCall(ApiCall.WEB_SETTINGS_SET_OFFSCREEN_PRE_RASTER, convertToParameterArray(enabled));
            recordApiCall(ApiCall.WEB_SETTINGS_SET_OFFSCREEN_PRE_RASTER);
            mAwSettings.setOffscreenPreRaster(enabled);
        }
    }

    @Override
    public boolean getOffscreenPreRaster() {
        try (TraceEvent event = TraceEvent.scoped(
                     "WebView.APICall.AndroidX.WEB_SETTINGS_GET_OFFSCREEN_PRE_RASTER")) {
            recordWebViewApiCall(ApiCall.WEB_SETTINGS_GET_OFFSCREEN_PRE_RASTER, convertToParameterArray());
            recordApiCall(ApiCall.WEB_SETTINGS_GET_OFFSCREEN_PRE_RASTER);
            return mAwSettings.getOffscreenPreRaster();
        }
    }

    @Override
    public void setSafeBrowsingEnabled(boolean enabled) {
        try (TraceEvent event = TraceEvent.scoped(
                     "WebView.APICall.AndroidX.WEB_SETTINGS_SET_SAFE_BROWSING_ENABLED")) {
            recordWebViewApiCall(ApiCall.WEB_SETTINGS_SET_SAFE_BROWSING_ENABLED, convertToParameterArray(enabled));
            recordApiCall(ApiCall.WEB_SETTINGS_SET_SAFE_BROWSING_ENABLED);
            mAwSettings.setSafeBrowsingEnabled(enabled);
        }
    }

    @Override
    public boolean getSafeBrowsingEnabled() {
        try (TraceEvent event = TraceEvent.scoped(
                     "WebView.APICall.AndroidX.WEB_SETTINGS_GET_SAFE_BROWSING_ENABLED")) {
            recordWebViewApiCall(ApiCall.WEB_SETTINGS_GET_SAFE_BROWSING_ENABLED, convertToParameterArray());
            recordApiCall(ApiCall.WEB_SETTINGS_GET_SAFE_BROWSING_ENABLED);
            return mAwSettings.getSafeBrowsingEnabled();
        }
    }

    @Override
    public void setDisabledActionModeMenuItems(int menuItems) {
        try (TraceEvent event = TraceEvent.scoped(
                     "WebView.APICall.AndroidX.WEB_SETTINGS_SET_DISABLED_ACTION_MODE_MENU_ITEMS")) {
            recordWebViewApiCall(ApiCall.WEB_SETTINGS_SET_DISABLED_ACTION_MODE_MENU_ITEMS, convertToParameterArray(menuItems));
            recordApiCall(ApiCall.WEB_SETTINGS_SET_DISABLED_ACTION_MODE_MENU_ITEMS);
            mAwSettings.setDisabledActionModeMenuItems(menuItems);
        }
    }

    @Override
    public int getDisabledActionModeMenuItems() {
        try (TraceEvent event = TraceEvent.scoped(
                     "WebView.APICall.AndroidX.WEB_SETTINGS_GET_DISABLED_ACTION_MODE_MENU_ITEMS")) {
            recordWebViewApiCall(ApiCall.WEB_SETTINGS_GET_DISABLED_ACTION_MODE_MENU_ITEMS, convertToParameterArray());
            recordApiCall(ApiCall.WEB_SETTINGS_GET_DISABLED_ACTION_MODE_MENU_ITEMS);
            return mAwSettings.getDisabledActionModeMenuItems();
        }
    }

    @Override
    public boolean getWillSuppressErrorPage() {
        try (TraceEvent event = TraceEvent.scoped(
                     "WebView.APICall.AndroidX.WEB_SETTINGS_GET_WILL_SUPPRESS_ERROR_PAGE")) {
            recordWebViewApiCall(ApiCall.WEB_SETTINGS_GET_WILL_SUPPRESS_ERROR_PAGE, convertToParameterArray());
            recordApiCall(ApiCall.WEB_SETTINGS_GET_WILL_SUPPRESS_ERROR_PAGE);
            return mAwSettings.getWillSuppressErrorPage();
        }
    }

    @Override
    public void setWillSuppressErrorPage(boolean suppressed) {
        try (TraceEvent event = TraceEvent.scoped(
                     "WebView.APICall.AndroidX.WEB_SETTINGS_SET_WILL_SUPPRESS_ERROR_PAGE")) {
            recordWebViewApiCall(ApiCall.WEB_SETTINGS_SET_WILL_SUPPRESS_ERROR_PAGE, convertToParameterArray(suppressed));
            recordApiCall(ApiCall.WEB_SETTINGS_SET_WILL_SUPPRESS_ERROR_PAGE);
            mAwSettings.setWillSuppressErrorPage(suppressed);
        }
    }

    @Override
    public void setForceDark(int forceDarkMode) {
        if (AwDarkMode.isSimplifiedDarkModeEnabled()) {
            Log.w(TAG, "setForceDark() is a no-op in an app with targetSdkVersion>=T");
            return;
        }
        try (TraceEvent event =
                        TraceEvent.scoped("WebView.APICall.AndroidX.WEB_SETTINGS_SET_FORCE_DARK")) {
            recordWebViewApiCall(ApiCall.WEB_SETTINGS_SET_FORCE_DARK, convertToParameterArray(forceDarkMode));
            recordApiCall(ApiCall.WEB_SETTINGS_SET_FORCE_DARK);
            mAwSettings.setForceDarkMode(forceDarkMode);
        }
    }

    @Override
    public int getForceDark() {
        try (TraceEvent event =
                        TraceEvent.scoped("WebView.APICall.AndroidX.WEB_SETTINGS_GET_FORCE_DARK")) {
            recordWebViewApiCall(ApiCall.WEB_SETTINGS_GET_FORCE_DARK, convertToParameterArray());
            recordApiCall(ApiCall.WEB_SETTINGS_GET_FORCE_DARK);
            if (AwDarkMode.isSimplifiedDarkModeEnabled()) {
                Log.w(TAG, "getForceDark() is a no-op in an app with targetSdkVersion>=T");
                return WebSettings.FORCE_DARK_AUTO;
            }
            return mAwSettings.getForceDarkMode();
        }
    }

    @Override
    public void setForceDarkBehavior(int forceDarkBehavior) {
        try (TraceEvent event = TraceEvent.scoped(
                     "WebView.APICall.AndroidX.WEB_SETTINGS_SET_FORCE_DARK_BEHAVIOR")) {
            recordWebViewApiCall(ApiCall.WEB_SETTINGS_SET_FORCE_DARK_BEHAVIOR, convertToParameterArray(forceDarkBehavior));
            recordApiCall(ApiCall.WEB_SETTINGS_SET_FORCE_DARK_BEHAVIOR);
            if (AwDarkMode.isSimplifiedDarkModeEnabled()) {
                Log.w(TAG, "setForceDarkBehavior() is a no-op in an app with targetSdkVersion>=T");
                return;
            }
            switch (forceDarkBehavior) {
                case ForceDarkBehavior.FORCE_DARK_ONLY:
                    mAwSettings.setForceDarkBehavior(AwSettings.FORCE_DARK_ONLY);
                    break;
                case ForceDarkBehavior.MEDIA_QUERY_ONLY:
                    mAwSettings.setForceDarkBehavior(AwSettings.MEDIA_QUERY_ONLY);
                    break;
                case ForceDarkBehavior.PREFER_MEDIA_QUERY_OVER_FORCE_DARK:
                    mAwSettings.setForceDarkBehavior(AwSettings.PREFER_MEDIA_QUERY_OVER_FORCE_DARK);
                    break;
            }
        }
    }

    @Override
    public int getForceDarkBehavior() {
        try (TraceEvent event = TraceEvent.scoped(
                     "WebView.APICall.AndroidX.WEB_SETTINGS_GET_FORCE_DARK_BEHAVIOR")) {
            recordWebViewApiCall(ApiCall.WEB_SETTINGS_GET_FORCE_DARK_BEHAVIOR, convertToParameterArray());
            recordApiCall(ApiCall.WEB_SETTINGS_GET_FORCE_DARK_BEHAVIOR);
            if (AwDarkMode.isSimplifiedDarkModeEnabled()) {
                Log.w(TAG, "getForceDarkBehavior() is a no-op in an app with targetSdkVersion>=T");
                return ForceDarkBehavior.PREFER_MEDIA_QUERY_OVER_FORCE_DARK;
            }
            switch (mAwSettings.getForceDarkBehavior()) {
                case AwSettings.FORCE_DARK_ONLY:
                    return ForceDarkBehavior.FORCE_DARK_ONLY;
                case AwSettings.MEDIA_QUERY_ONLY:
                    return ForceDarkBehavior.MEDIA_QUERY_ONLY;
                case AwSettings.PREFER_MEDIA_QUERY_OVER_FORCE_DARK:
                    return ForceDarkBehavior.PREFER_MEDIA_QUERY_OVER_FORCE_DARK;
            }
            return ForceDarkBehavior.PREFER_MEDIA_QUERY_OVER_FORCE_DARK;
        }
    }

    @Override
    public void setAlgorithmicDarkeningAllowed(boolean allow) {
        try (TraceEvent event = TraceEvent.scoped(
                     "WebView.APICall.AndroidX.WEB_SETTINGS_SET_ALGORITHMIC_DARKENING_ALLOWED")) {
            recordWebViewApiCall(ApiCall.WEB_SETTINGS_SET_ALGORITHMIC_DARKENING_ALLOWED, convertToParameterArray(allow));
            recordApiCall(ApiCall.WEB_SETTINGS_SET_ALGORITHMIC_DARKENING_ALLOWED);
            if (!AwDarkMode.isSimplifiedDarkModeEnabled()) {
                Log.w(TAG,
                        "setAlgorithmicDarkeningAllowed() is a no-op in an app with"
                                + "targetSdkVersion<T");
                return;
            }
            mAwSettings.setAlgorithmicDarkeningAllowed(allow);
        }
    }

    @Override
    public boolean isAlgorithmicDarkeningAllowed() {
        try (TraceEvent event = TraceEvent.scoped(
                     "WebView.APICall.AndroidX.WEB_SETTINGS_IS_ALGORITHMIC_DARKENING_ALLOWED")) {
            recordWebViewApiCall(ApiCall.WEB_SETTINGS_IS_ALGORITHMIC_DARKENING_ALLOWED, convertToParameterArray());
            recordApiCall(ApiCall.WEB_SETTINGS_IS_ALGORITHMIC_DARKENING_ALLOWED);
            if (!AwDarkMode.isSimplifiedDarkModeEnabled()) {
                Log.w(TAG,
                        "isAlgorithmicDarkeningAllowed() is a no-op in an app with "
                                + "targetSdkVersion<T");
                return false;
            }
            return mAwSettings.isAlgorithmicDarkeningAllowed();
        }
    }

    @Override
    public void setWebAuthnSupport(int support) {
        // Currently a no-op while this functionality is built out.
    }

    @Override
    public int getWebAuthnSupport() {
        // Currently a no-op while this functionality is built out.
        return WebAuthnSupport.NONE;
    }

    @Override
    public void setRequestedWithHeaderOriginAllowList(Set<String> allowedOriginRules) {
        try (TraceEvent event = TraceEvent.scoped(
                     "WebView.APICall.AndroidX.WEB_SETTINGS_SET_REQUESTED_WITH_HEADER_ORIGIN_ALLOWLIST")) {
            recordWebViewApiCall(ApiCall.WEB_SETTINGS_SET_REQUESTED_WITH_HEADER_ORIGIN_ALLOWLIST, convertToParameterArray(allowedOriginRules));
            recordApiCall(ApiCall.WEB_SETTINGS_SET_REQUESTED_WITH_HEADER_ORIGIN_ALLOWLIST);
            mAwSettings.setRequestedWithHeaderOriginAllowList(allowedOriginRules);
        }
    }

    @Override
    public Set<String> getRequestedWithHeaderOriginAllowList() {
        try (TraceEvent event = TraceEvent.scoped(
                     "WebView.APICall.AndroidX.WEB_SETTINGS_GET_REQUESTED_WITH_HEADER_ORIGIN_ALLOWLIST")) {
            recordWebViewApiCall(ApiCall.WEB_SETTINGS_GET_REQUESTED_WITH_HEADER_ORIGIN_ALLOWLIST, convertToParameterArray());
            recordApiCall(ApiCall.WEB_SETTINGS_GET_REQUESTED_WITH_HEADER_ORIGIN_ALLOWLIST);
            return mAwSettings.getRequestedWithHeaderOriginAllowList();
        }
    }

    @Override
    public void setEnterpriseAuthenticationAppLinkPolicyEnabled(boolean enabled) {
        try (TraceEvent event = TraceEvent.scoped(
                     "WebView.APICall.AndroidX.WEB_SETTINGS_SET_ENTERPRISE_AUTHENTICATION_APP_LINK_POLICY_ENABLED")) {
            recordWebViewApiCall(ApiCall.WEB_SETTINGS_SET_ENTERPRISE_AUTHENTICATION_APP_LINK_POLICY_ENABLED, convertToParameterArray(enabled));
            recordApiCall(
                    ApiCall.WEB_SETTINGS_SET_ENTERPRISE_AUTHENTICATION_APP_LINK_POLICY_ENABLED);
            mAwSettings.setEnterpriseAuthenticationAppLinkPolicyEnabled(enabled);
        }
    }
    @Override
    public boolean getEnterpriseAuthenticationAppLinkPolicyEnabled() {
        try (TraceEvent event = TraceEvent.scoped(
                     "WebView.APICall.AndroidX.WEB_SETTINGS_GET_ENTERPRISE_AUTHENTICATION_APP_LINK_POLICY_ENABLED")) {
            recordWebViewApiCall(ApiCall.WEB_SETTINGS_GET_ENTERPRISE_AUTHENTICATION_APP_LINK_POLICY_ENABLED, convertToParameterArray());
            recordApiCall(
                    ApiCall.WEB_SETTINGS_GET_ENTERPRISE_AUTHENTICATION_APP_LINK_POLICY_ENABLED);
            return mAwSettings.getEnterpriseAuthenticationAppLinkPolicyEnabled();
        }
    }

    @Override
    public void setUserAgentMetadataFromMap(Map<String, Object> uaMetadata) {
        try (TraceEvent event = TraceEvent.scoped(
                     "WebView.APICall.AndroidX.WEB_SETTINGS_SET_USER_AGENT_METADATA")) {
            recordWebViewApiCall(ApiCall.WEB_SETTINGS_SET_USER_AGENT_METADATA, convertToParameterArray(uaMetadata));
            recordApiCall(ApiCall.WEB_SETTINGS_SET_USER_AGENT_METADATA);
            mAwSettings.setUserAgentMetadataFromMap(uaMetadata);
        }
    }
    @Override
    public Map<String, Object> getUserAgentMetadataMap() {
        try (TraceEvent event = TraceEvent.scoped(
                     "WebView.APICall.AndroidX.WEB_SETTINGS_GET_USER_AGENT_METADATA")) {
            recordWebViewApiCall(ApiCall.WEB_SETTINGS_GET_USER_AGENT_METADATA, convertToParameterArray());
            recordApiCall(ApiCall.WEB_SETTINGS_GET_USER_AGENT_METADATA);
            return mAwSettings.getUserAgentMetadataMap();
        }
    }
}
