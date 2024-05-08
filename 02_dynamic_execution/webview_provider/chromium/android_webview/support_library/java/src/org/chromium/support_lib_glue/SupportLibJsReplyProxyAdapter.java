// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.support_lib_glue;

import static org.chromium.support_lib_glue.SupportLibWebViewChromiumFactory.recordApiCall;
import static org.chromium.support_lib_glue.SupportLibWebViewChromiumFactory.recordWebViewApiCall;
import static org.chromium.support_lib_glue.SupportLibWebViewChromiumFactory.convertToParameterArray;

import org.chromium.android_webview.AwSupportLibIsomorphic;
import org.chromium.android_webview.JsReplyProxy;
import org.chromium.base.TraceEvent;
import org.chromium.content_public.browser.MessagePayload;
import org.chromium.support_lib_boundary.JsReplyProxyBoundaryInterface;
import org.chromium.support_lib_glue.SupportLibWebViewChromiumFactory.ApiCall;

import java.lang.reflect.InvocationHandler;

/**
 * Adapter between JsReplyProxyBoundaryInterface and JsReplyProxy.
 */
class SupportLibJsReplyProxyAdapter
        extends IsomorphicAdapter implements JsReplyProxyBoundaryInterface {
    private JsReplyProxy mReplyProxy;

    public SupportLibJsReplyProxyAdapter(JsReplyProxy replyProxy) {
        mReplyProxy = replyProxy;
    }

    @Override
    public void postMessage(String message) {
        try (TraceEvent event =
                        TraceEvent.scoped("WebView.APICall.AndroidX.JS_REPLY_POST_MESSAGE")) {
            recordWebViewApiCall(ApiCall.JS_REPLY_POST_MESSAGE, convertToParameterArray(message));
            recordApiCall(ApiCall.JS_REPLY_POST_MESSAGE);
            mReplyProxy.postMessage(new MessagePayload(message));
        }
    }

    @Override
    public void postMessageWithPayload(/* MessagePayload */ InvocationHandler payload) {
        try (TraceEvent event = TraceEvent.scoped(
                     "WebView.APICall.AndroidX.JS_REPLY_POST_MESSAGE_WITH_PAYLOAD")) {
            recordWebViewApiCall(ApiCall.JS_REPLY_POST_MESSAGE_WITH_PAYLOAD, convertToParameterArray(payload));
            recordApiCall(ApiCall.JS_REPLY_POST_MESSAGE_WITH_PAYLOAD);
            mReplyProxy.postMessage(SupportLibWebMessagePayloadAdapter.toMessagePayload(payload));
        }
    }

    @Override
    /* package */ AwSupportLibIsomorphic getPeeredObject() {
        return mReplyProxy;
    }
}
