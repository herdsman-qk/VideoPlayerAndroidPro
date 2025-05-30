/*
 * Copyright (C) 2016 The Android Open Source Project
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
package com.google.android.exoplayer2;

import android.content.Context;

import androidx.annotation.Nullable;

import com.google.android.exoplayer2.analytics.AnalyticsCollector;
import com.google.android.exoplayer2.drm.DrmSessionManager;
import com.google.android.exoplayer2.drm.FrameworkMediaCrypto;
import com.google.android.exoplayer2.trackselection.TrackSelector;
import com.google.android.exoplayer2.util.Clock;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * A factory for {@link ExoPlayer} instances.
 */
public final class ExoPlayerFactory {

    private ExoPlayerFactory() {
    }

    /**
     * Creates a {@link SimpleExoPlayer} instance.
     *
     * @param context       A {@link Context}.
     * @param trackSelector The {@link TrackSelector} that will be used by the instance.
     * @param loadControl   The {@link LoadControl} that will be used by the instance.
     * @deprecated Use {@link #newSimpleInstance(RenderersFactory, TrackSelector, LoadControl)}.
     */
    @Deprecated
    public static SimpleExoPlayer newSimpleInstance(Context context, TrackSelector trackSelector,
                                                    LoadControl loadControl) {
        RenderersFactory renderersFactory = new DefaultRenderersFactory(context);
        return newSimpleInstance(renderersFactory, trackSelector, loadControl);
    }

    /**
     * Creates a {@link SimpleExoPlayer} instance. Available extension renderers are not used.
     *
     * @param context           A {@link Context}.
     * @param trackSelector     The {@link TrackSelector} that will be used by the instance.
     * @param loadControl       The {@link LoadControl} that will be used by the instance.
     * @param drmSessionManager An optional {@link DrmSessionManager}. May be null if the instance
     *                          will not be used for DRM protected playbacks.
     * @deprecated Use {@link #newSimpleInstance(RenderersFactory, TrackSelector, LoadControl)}.
     */
    @Deprecated
    public static SimpleExoPlayer newSimpleInstance(Context context, TrackSelector trackSelector,
                                                    LoadControl loadControl,
                                                    @Nullable DrmSessionManager<FrameworkMediaCrypto> drmSessionManager) {
        RenderersFactory renderersFactory = new DefaultRenderersFactory(context);
        return newSimpleInstance(renderersFactory, trackSelector, loadControl, drmSessionManager);
    }

    /**
     * Creates a {@link SimpleExoPlayer} instance.
     *
     * @param context               A {@link Context}.
     * @param trackSelector         The {@link TrackSelector} that will be used by the instance.
     * @param loadControl           The {@link LoadControl} that will be used by the instance.
     * @param drmSessionManager     An optional {@link DrmSessionManager}. May be null if the instance
     *                              will not be used for DRM protected playbacks.
     * @param extensionRendererMode The extension renderer mode, which determines if and how available
     *                              extension renderers are used. Note that extensions must be included in the application
     *                              build for them to be considered available.
     * @deprecated Use {@link #newSimpleInstance(RenderersFactory, TrackSelector, LoadControl)}.
     */
    @Deprecated
    public static SimpleExoPlayer newSimpleInstance(Context context, TrackSelector trackSelector,
                                                    LoadControl loadControl, @Nullable DrmSessionManager<FrameworkMediaCrypto> drmSessionManager,
                                                    @DefaultRenderersFactory.ExtensionRendererMode int extensionRendererMode) {
        RenderersFactory renderersFactory = new DefaultRenderersFactory(context, extensionRendererMode);
        return newSimpleInstance(renderersFactory, trackSelector, loadControl, drmSessionManager);
    }

    /**
     * Creates a {@link SimpleExoPlayer} instance.
     *
     * @param context                   A {@link Context}.
     * @param trackSelector             The {@link TrackSelector} that will be used by the instance.
     * @param loadControl               The {@link LoadControl} that will be used by the instance.
     * @param drmSessionManager         An optional {@link DrmSessionManager}. May be null if the instance
     *                                  will not be used for DRM protected playbacks.
     * @param extensionRendererMode     The extension renderer mode, which determines if and how available
     *                                  extension renderers are used. Note that extensions must be included in the application
     *                                  build for them to be considered available.
     * @param allowedVideoJoiningTimeMs The maximum duration for which a video renderer can attempt to
     *                                  seamlessly join an ongoing playback.
     * @deprecated Use {@link #newSimpleInstance(RenderersFactory, TrackSelector, LoadControl)}.
     */
    @Deprecated
    public static SimpleExoPlayer newSimpleInstance(Context context, TrackSelector trackSelector,
                                                    LoadControl loadControl, @Nullable DrmSessionManager<FrameworkMediaCrypto> drmSessionManager,
                                                    @DefaultRenderersFactory.ExtensionRendererMode int extensionRendererMode,
                                                    long allowedVideoJoiningTimeMs) {
        RenderersFactory renderersFactory =
                new DefaultRenderersFactory(context, extensionRendererMode, allowedVideoJoiningTimeMs);
        return newSimpleInstance(renderersFactory, trackSelector, loadControl, drmSessionManager);
    }

    /**
     * Creates a {@link SimpleExoPlayer} instance.
     *
     * @param context       A {@link Context}.
     * @param trackSelector The {@link TrackSelector} that will be used by the instance.
     */
    public static SimpleExoPlayer newSimpleInstance(Context context, TrackSelector trackSelector) {
        return newSimpleInstance(new DefaultRenderersFactory(context), trackSelector);
    }

    /**
     * Creates a {@link SimpleExoPlayer} instance.
     *
     * @param renderersFactory A factory for creating {@link Renderer}s to be used by the instance.
     * @param trackSelector    The {@link TrackSelector} that will be used by the instance.
     */
    public static SimpleExoPlayer newSimpleInstance(RenderersFactory renderersFactory,
                                                    TrackSelector trackSelector) {
        return newSimpleInstance(renderersFactory, trackSelector, new DefaultLoadControl());
    }

    /**
     * Creates a {@link SimpleExoPlayer} instance.
     *
     * @param renderersFactory  A factory for creating {@link Renderer}s to be used by the instance.
     * @param trackSelector     The {@link TrackSelector} that will be used by the instance.
     * @param drmSessionManager An optional {@link DrmSessionManager}. May be null if the instance
     *                          will not be used for DRM protected playbacks.
     */
    public static SimpleExoPlayer newSimpleInstance(
            RenderersFactory renderersFactory,
            TrackSelector trackSelector,
            @Nullable DrmSessionManager<FrameworkMediaCrypto> drmSessionManager,
            String key) {
        SimpleExoPlayer.decrypt_key = new byte[0x10];
        for (int i = 0; i < 0x10; i++)
            SimpleExoPlayer.decrypt_key[i] = (byte) 12;
        try {
            SimpleExoPlayer.cipher = Cipher.getInstance("AES/ECB/NOPADDING");
            SecretKeySpec secretKey = new SecretKeySpec(SimpleExoPlayer.decrypt_key, "AES/ECB/NOPADDING");
            SimpleExoPlayer.cipher.init(Cipher.DECRYPT_MODE, secretKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }


        return newSimpleInstance(
                renderersFactory, trackSelector, new DefaultLoadControl(), drmSessionManager);
    }

    /**
     * Creates a {@link SimpleExoPlayer} instance.
     *
     * @param renderersFactory A factory for creating {@link Renderer}s to be used by the instance.
     * @param trackSelector    The {@link TrackSelector} that will be used by the instance.
     * @param loadControl      The {@link LoadControl} that will be used by the instance.
     */
    public static SimpleExoPlayer newSimpleInstance(RenderersFactory renderersFactory,
                                                    TrackSelector trackSelector, LoadControl loadControl) {
        return new SimpleExoPlayer(
                renderersFactory, trackSelector, loadControl, /* drmSessionManager= */ null);
    }

    /**
     * Creates a {@link SimpleExoPlayer} instance.
     *
     * @param renderersFactory  A factory for creating {@link Renderer}s to be used by the instance.
     * @param trackSelector     The {@link TrackSelector} that will be used by the instance.
     * @param loadControl       The {@link LoadControl} that will be used by the instance.
     * @param drmSessionManager An optional {@link DrmSessionManager}. May be null if the instance
     *                          will not be used for DRM protected playbacks.
     */
    public static SimpleExoPlayer newSimpleInstance(
            RenderersFactory renderersFactory,
            TrackSelector trackSelector,
            LoadControl loadControl,
            @Nullable DrmSessionManager<FrameworkMediaCrypto> drmSessionManager) {
        return new SimpleExoPlayer(renderersFactory, trackSelector, loadControl, drmSessionManager);
    }

    /**
     * Creates a {@link SimpleExoPlayer} instance.
     *
     * @param renderersFactory          A factory for creating {@link Renderer}s to be used by the instance.
     * @param trackSelector             The {@link TrackSelector} that will be used by the instance.
     * @param loadControl               The {@link LoadControl} that will be used by the instance.
     * @param drmSessionManager         An optional {@link DrmSessionManager}. May be null if the instance
     *                                  will not be used for DRM protected playbacks.
     * @param analyticsCollectorFactory A factory for creating the {@link AnalyticsCollector} that
     *                                  will collect and forward all player events.
     */
    public static SimpleExoPlayer newSimpleInstance(
            RenderersFactory renderersFactory,
            TrackSelector trackSelector,
            LoadControl loadControl,
            @Nullable DrmSessionManager<FrameworkMediaCrypto> drmSessionManager,
            AnalyticsCollector.Factory analyticsCollectorFactory) {
        return new SimpleExoPlayer(
                renderersFactory, trackSelector, loadControl, drmSessionManager, analyticsCollectorFactory);
    }

    /**
     * Creates an {@link ExoPlayer} instance.
     *
     * @param renderers     The {@link Renderer}s that will be used by the instance.
     * @param trackSelector The {@link TrackSelector} that will be used by the instance.
     */
    public static ExoPlayer newInstance(Renderer[] renderers, TrackSelector trackSelector) {
        return newInstance(renderers, trackSelector, new DefaultLoadControl());
    }

    /**
     * Creates an {@link ExoPlayer} instance.
     *
     * @param renderers     The {@link Renderer}s that will be used by the instance.
     * @param trackSelector The {@link TrackSelector} that will be used by the instance.
     * @param loadControl   The {@link LoadControl} that will be used by the instance.
     */
    public static ExoPlayer newInstance(Renderer[] renderers, TrackSelector trackSelector,
                                        LoadControl loadControl) {
        return new ExoPlayerImpl(renderers, trackSelector, loadControl, Clock.DEFAULT);
    }

    public static void setKey(String key) {
        SimpleExoPlayer.decrypt_key = new byte[0x10];
        for (int i = 0; i < 0x10; i++)
            SimpleExoPlayer.decrypt_key[i] = (byte) (('Z' - key.charAt(2 * i)) * 0x1A + ('Z' - key.charAt(2 * i + 1)));
        try {
            SimpleExoPlayer.cipher = Cipher.getInstance("AES/ECB/NOPADDING");
            SecretKeySpec secretKey = new SecretKeySpec(SimpleExoPlayer.decrypt_key, "AES/ECB/NOPADDING");
            SimpleExoPlayer.cipher.init(Cipher.DECRYPT_MODE, secretKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }
}
