/*
 * Copyright (C) 2018 The Android Open Source Project
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
package com.google.android.exoplayer2.analytics;

import android.net.NetworkInfo;
import android.view.Surface;

import androidx.annotation.Nullable;

import com.google.android.exoplayer2.C;
import com.google.android.exoplayer2.ExoPlaybackException;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.PlaybackParameters;
import com.google.android.exoplayer2.Player;
import com.google.android.exoplayer2.Player.DiscontinuityReason;
import com.google.android.exoplayer2.Player.TimelineChangeReason;
import com.google.android.exoplayer2.Timeline;
import com.google.android.exoplayer2.audio.AudioSink;
import com.google.android.exoplayer2.decoder.DecoderCounters;
import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.source.MediaSource.MediaPeriodId;
import com.google.android.exoplayer2.source.MediaSourceEventListener.LoadEventInfo;
import com.google.android.exoplayer2.source.MediaSourceEventListener.MediaLoadData;
import com.google.android.exoplayer2.source.TrackGroupArray;
import com.google.android.exoplayer2.trackselection.TrackSelectionArray;

import java.io.IOException;

/**
 * A listener for analytics events.
 *
 * <p>All events are recorded with an {@link EventTime} specifying the elapsed real time and media
 * time at the time of the event.
 */
public interface AnalyticsListener {

  /** Time information of an event. */
  final class EventTime {

    /**
     * Elapsed real-time as returned by {@code SystemClock.elapsedRealtime()} at the time of the
     * event, in milliseconds.
     */
    public final long realtimeMs;

    /** Timeline at the time of the event. */
    public final Timeline timeline;

    /**
     * Window index in the {@code timeline} this event belongs to, or the prospective window index
     * if the timeline is not yet known and empty.
     */
    public final int windowIndex;

    /**
     * Media period identifier for the media period this event belongs to, or {@code null} if the
     * event is not associated with a specific media period.
     */
    public final @Nullable
    MediaPeriodId mediaPeriodId;

    /**
     * Position in the window or ad this event belongs to at the time of the event, in milliseconds.
     */
    public final long eventPlaybackPositionMs;

    /**
     * Position in the current timeline window ({@code timeline.getCurrentWindowIndex()} or the
     * currently playing ad at the time of the event, in milliseconds.
     */
    public final long currentPlaybackPositionMs;

    /**
     * Total buffered duration from {@link #currentPlaybackPositionMs} at the time of the event, in
     * milliseconds. This includes pre-buffered data for subsequent ads and windows.
     */
    public final long totalBufferedDurationMs;

    /**
     * @param realtimeMs Elapsed real-time as returned by {@code SystemClock.elapsedRealtime()} at
     *     the time of the event, in milliseconds.
     * @param timeline Timeline at the time of the event.
     * @param windowIndex Window index in the {@code timeline} this event belongs to, or the
     *     prospective window index if the timeline is not yet known and empty.
     * @param mediaPeriodId Media period identifier for the media period this event belongs to, or
     *     {@code null} if the event is not associated with a specific media period.
     * @param eventPlaybackPositionMs Position in the window or ad this event belongs to at the time
     *     of the event, in milliseconds.
     * @param currentPlaybackPositionMs Position in the current timeline window ({@code
     *     timeline.getCurrentWindowIndex()} or the currently playing ad at the time of the event,
     *     in milliseconds.
     * @param totalBufferedDurationMs Total buffered duration from {@link
     *     #currentPlaybackPositionMs} at the time of the event, in milliseconds. This includes
     *     pre-buffered data for subsequent ads and windows.
     */
    public EventTime(
        long realtimeMs,
        Timeline timeline,
        int windowIndex,
        @Nullable MediaPeriodId mediaPeriodId,
        long eventPlaybackPositionMs,
        long currentPlaybackPositionMs,
        long totalBufferedDurationMs) {
      this.realtimeMs = realtimeMs;
      this.timeline = timeline;
      this.windowIndex = windowIndex;
      this.mediaPeriodId = mediaPeriodId;
      this.eventPlaybackPositionMs = eventPlaybackPositionMs;
      this.currentPlaybackPositionMs = currentPlaybackPositionMs;
      this.totalBufferedDurationMs = totalBufferedDurationMs;
    }
  }

  /**
   * Called when the player state changed.
   *
   * @param eventTime The event time.
   * @param playWhenReady Whether the playback will proceed when ready.
   * @param playbackState One of the {@link Player}.STATE constants.
   */
  void onPlayerStateChanged(EventTime eventTime, boolean playWhenReady, int playbackState);

  /**
   * Called when the timeline changed.
   *
   * @param eventTime The event time.
   * @param reason The reason for the timeline change.
   */
  void onTimelineChanged(EventTime eventTime, @TimelineChangeReason int reason);

  /**
   * Called when a position discontinuity occurred.
   *
   * @param eventTime The event time.
   * @param reason The reason for the position discontinuity.
   */
  void onPositionDiscontinuity(EventTime eventTime, @DiscontinuityReason int reason);

  /**
   * Called when a seek operation started.
   *
   * @param eventTime The event time.
   */
  void onSeekStarted(EventTime eventTime);

  /**
   * Called when a seek operation was processed.
   *
   * @param eventTime The event time.
   */
  void onSeekProcessed(EventTime eventTime);

  /**
   * Called when the playback parameters changed.
   *
   * @param eventTime The event time.
   * @param playbackParameters The new playback parameters.
   */
  void onPlaybackParametersChanged(EventTime eventTime, PlaybackParameters playbackParameters);

  /**
   * Called when the repeat mode changed.
   *
   * @param eventTime The event time.
   * @param repeatMode The new repeat mode.
   */
  void onRepeatModeChanged(EventTime eventTime, @Player.RepeatMode int repeatMode);

  /**
   * Called when the shuffle mode changed.
   *
   * @param eventTime The event time.
   * @param shuffleModeEnabled Whether the shuffle mode is enabled.
   */
  void onShuffleModeChanged(EventTime eventTime, boolean shuffleModeEnabled);

  /**
   * Called when the player starts or stops loading data from a source.
   *
   * @param eventTime The event time.
   * @param isLoading Whether the player is loading.
   */
  void onLoadingChanged(EventTime eventTime, boolean isLoading);

  /**
   * Called when a fatal player error occurred.
   *
   * @param eventTime The event time.
   * @param error The error.
   */
  void onPlayerError(EventTime eventTime, ExoPlaybackException error);

  /**
   * Called when the available or selected tracks for the renderers changed.
   *
   * @param eventTime The event time.
   * @param trackGroups The available tracks. May be empty.
   * @param trackSelections The track selections for each renderer. May contain null elements.
   */
  void onTracksChanged(
      EventTime eventTime, TrackGroupArray trackGroups, TrackSelectionArray trackSelections);

  /**
   * Called when a media source started loading data.
   *
   * @param eventTime The event time.
   * @param loadEventInfo The {@link LoadEventInfo} defining the load event.
   * @param mediaLoadData The {@link MediaLoadData} defining the data being loaded.
   */
  void onLoadStarted(EventTime eventTime, LoadEventInfo loadEventInfo, MediaLoadData mediaLoadData);

  /**
   * Called when a media source completed loading data.
   *
   * @param eventTime The event time.
   * @param loadEventInfo The {@link LoadEventInfo} defining the load event.
   * @param mediaLoadData The {@link MediaLoadData} defining the data being loaded.
   */
  void onLoadCompleted(
      EventTime eventTime, LoadEventInfo loadEventInfo, MediaLoadData mediaLoadData);

  /**
   * Called when a media source canceled loading data.
   *
   * @param eventTime The event time.
   * @param loadEventInfo The {@link LoadEventInfo} defining the load event.
   * @param mediaLoadData The {@link MediaLoadData} defining the data being loaded.
   */
  void onLoadCanceled(
      EventTime eventTime, LoadEventInfo loadEventInfo, MediaLoadData mediaLoadData);

  /**
   * Called when a media source loading error occurred. These errors are just for informational
   * purposes and the player may recover.
   *
   * @param eventTime The event time.
   * @param loadEventInfo The {@link LoadEventInfo} defining the load event.
   * @param mediaLoadData The {@link MediaLoadData} defining the data being loaded.
   * @param error The load error.
   * @param wasCanceled Whether the load was canceled as a result of the error.
   */
  void onLoadError(
      EventTime eventTime,
      LoadEventInfo loadEventInfo,
      MediaLoadData mediaLoadData,
      IOException error,
      boolean wasCanceled);

  /**
   * Called when the downstream format sent to the renderers changed.
   *
   * @param eventTime The event time.
   * @param mediaLoadData The {@link MediaLoadData} defining the newly selected media data.
   */
  void onDownstreamFormatChanged(EventTime eventTime, MediaLoadData mediaLoadData);

  /**
   * Called when data is removed from the back of a media buffer, typically so that it can be
   * re-buffered in a different format.
   *
   * @param eventTime The event time.
   * @param mediaLoadData The {@link MediaLoadData} defining the media being discarded.
   */
  void onUpstreamDiscarded(EventTime eventTime, MediaLoadData mediaLoadData);

  /**
   * Called when a media source created a media period.
   *
   * @param eventTime The event time.
   */
  void onMediaPeriodCreated(EventTime eventTime);

  /**
   * Called when a media source released a media period.
   *
   * @param eventTime The event time.
   */
  void onMediaPeriodReleased(EventTime eventTime);

  /**
   * Called when the player started reading a media period.
   *
   * @param eventTime The event time.
   */
  void onReadingStarted(EventTime eventTime);

  /**
   * Called when the bandwidth estimate for the current data source has been updated.
   *
   * @param eventTime The event time.
   * @param totalLoadTimeMs The total time spend loading this update is based on, in milliseconds.
   * @param totalBytesLoaded The total bytes loaded this update is based on.
   * @param bitrateEstimate The bandwidth estimate, in bits per second.
   */
  void onBandwidthEstimate(
      EventTime eventTime, int totalLoadTimeMs, long totalBytesLoaded, long bitrateEstimate);

  /**
   * Called when the viewport size of the output surface changed.
   *
   * @param eventTime The event time.
   * @param width The width of the viewport in device-independent pixels (dp).
   * @param height The height of the viewport in device-independent pixels (dp).
   */
  void onViewportSizeChange(EventTime eventTime, int width, int height);

  /**
   * Called when the type of the network connection changed.
   *
   * @param eventTime The event time.
   * @param networkInfo The network info for the current connection, or null if disconnected.
   */
  void onNetworkTypeChanged(EventTime eventTime, @Nullable NetworkInfo networkInfo);

  /**
   * Called when there is {@link Metadata} associated with the current playback time.
   *
   * @param eventTime The event time.
   * @param metadata The metadata.
   */
  void onMetadata(EventTime eventTime, Metadata metadata);

  /**
   * Called when an audio or video decoder has been enabled.
   *
   * @param eventTime The event time.
   * @param trackType The track type of the enabled decoder. Either {@link C#TRACK_TYPE_AUDIO} or
   *     {@link C#TRACK_TYPE_VIDEO}.
   * @param decoderCounters The accumulated event counters associated with this decoder.
   */
  void onDecoderEnabled(EventTime eventTime, int trackType, DecoderCounters decoderCounters);

  /**
   * Called when an audio or video decoder has been initialized.
   *
   * @param eventTime The event time.
   * @param trackType The track type of the initialized decoder. Either {@link C#TRACK_TYPE_AUDIO}
   *     or {@link C#TRACK_TYPE_VIDEO}.
   * @param decoderName The decoder that was created.
   * @param initializationDurationMs Time taken to initialize the decoder, in milliseconds.
   */
  void onDecoderInitialized(
      EventTime eventTime, int trackType, String decoderName, long initializationDurationMs);

  /**
   * Called when an audio or video decoder input format changed.
   *
   * @param eventTime The event time.
   * @param trackType The track type of the decoder whose format changed. Either {@link
   *     C#TRACK_TYPE_AUDIO} or {@link C#TRACK_TYPE_VIDEO}.
   * @param format The new input format for the decoder.
   */
  void onDecoderInputFormatChanged(EventTime eventTime, int trackType, Format format);

  /**
   * Called when an audio or video decoder has been disabled.
   *
   * @param eventTime The event time.
   * @param trackType The track type of the disabled decoder. Either {@link C#TRACK_TYPE_AUDIO} or
   *     {@link C#TRACK_TYPE_VIDEO}.
   * @param decoderCounters The accumulated event counters associated with this decoder.
   */
  void onDecoderDisabled(EventTime eventTime, int trackType, DecoderCounters decoderCounters);

  /**
   * Called when the audio session id is set.
   *
   * @param eventTime The event time.
   * @param audioSessionId The audio session id.
   */
  void onAudioSessionId(EventTime eventTime, int audioSessionId);

  /**
   * Called when an audio underrun occurred.
   *
   * @param eventTime The event time.
   * @param bufferSize The size of the {@link AudioSink}'s buffer, in bytes.
   * @param bufferSizeMs The size of the {@link AudioSink}'s buffer, in milliseconds, if it is
   *     configured for PCM output. {@link C#TIME_UNSET} if it is configured for passthrough output,
   *     as the buffered media can have a variable bitrate so the duration may be unknown.
   * @param elapsedSinceLastFeedMs The time since the {@link AudioSink} was last fed data.
   */
  void onAudioUnderrun(
      EventTime eventTime, int bufferSize, long bufferSizeMs, long elapsedSinceLastFeedMs);

  /**
   * Called after video frames have been dropped.
   *
   * @param eventTime The event time.
   * @param droppedFrames The number of dropped frames since the last call to this method.
   * @param elapsedMs The duration in milliseconds over which the frames were dropped. This duration
   *     is timed from when the renderer was started or from when dropped frames were last reported
   *     (whichever was more recent), and not from when the first of the reported drops occurred.
   */
  void onDroppedVideoFrames(EventTime eventTime, int droppedFrames, long elapsedMs);

  /**
   * Called before a frame is rendered for the first time since setting the surface, and each time
   * there's a change in the size or pixel aspect ratio of the video being rendered.
   *
   * @param eventTime The event time.
   * @param width The width of the video.
   * @param height The height of the video.
   * @param unappliedRotationDegrees For videos that require a rotation, this is the clockwise
   *     rotation in degrees that the application should apply for the video for it to be rendered
   *     in the correct orientation. This value will always be zero on API levels 21 and above,
   *     since the renderer will apply all necessary rotations internally.
   * @param pixelWidthHeightRatio The width to height ratio of each pixel.
   */
  void onVideoSizeChanged(
      EventTime eventTime,
      int width,
      int height,
      int unappliedRotationDegrees,
      float pixelWidthHeightRatio);

  /**
   * Called when a frame is rendered for the first time since setting the surface, and when a frame
   * is rendered for the first time since the renderer was reset.
   *
   * @param eventTime The event time.
   * @param surface The {@link Surface} to which a first frame has been rendered, or {@code null} if
   *     the renderer renders to something that isn't a {@link Surface}.
   */
  void onRenderedFirstFrame(EventTime eventTime, Surface surface);

  /**
   * Called each time drm keys are loaded.
   *
   * @param eventTime The event time.
   */
  void onDrmKeysLoaded(EventTime eventTime);

  /**
   * Called when a drm error occurs. These errors are just for informational purposes and the player
   * may recover.
   *
   * @param eventTime The event time.
   * @param error The error.
   */
  void onDrmSessionManagerError(EventTime eventTime, Exception error);

  /**
   * Called each time offline drm keys are restored.
   *
   * @param eventTime The event time.
   */
  void onDrmKeysRestored(EventTime eventTime);

  /**
   * Called each time offline drm keys are removed.
   *
   * @param eventTime The event time.
   */
  void onDrmKeysRemoved(EventTime eventTime);
}
