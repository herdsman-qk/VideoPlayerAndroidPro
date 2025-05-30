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
package com.google.android.exoplayer2.audio;

import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.media.AudioFormat;
import android.media.AudioManager;
import android.media.AudioTrack;
import android.os.ConditionVariable;
import android.os.SystemClock;
import android.util.Log;

import androidx.annotation.IntDef;
import androidx.annotation.Nullable;

import com.google.android.exoplayer2.C;
import com.google.android.exoplayer2.PlaybackParameters;
import com.google.android.exoplayer2.util.Assertions;
import com.google.android.exoplayer2.util.Util;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;

/**
 * Plays audio data. The implementation delegates to an {@link AudioTrack} and handles playback
 * position smoothing, non-blocking writes and reconfiguration.
 * <p>
 * If tunneling mode is enabled, care must be taken that audio processors do not output buffers with
 * a different duration than their input, and buffer processors must produce output corresponding to
 * their last input immediately after that input is queued. This means that, for example, speed
 * adjustment is not possible while using tunneling.
 */
public final class DefaultAudioSink implements AudioSink {

  /**
   * Thrown when the audio track has provided a spurious timestamp, if {@link
   * #failOnSpuriousAudioTimestamp} is set.
   */
  public static final class InvalidAudioTrackTimestampException extends RuntimeException {

    /**
     * Creates a new invalid timestamp exception with the specified message.
     *
     * @param message The detail message for this exception.
     */
    private InvalidAudioTrackTimestampException(String message) {
      super(message);
    }

  }

  /**
   * Provides a chain of audio processors, which are used for any user-defined processing and
   * applying playback parameters (if supported). Because applying playback parameters can skip and
   * stretch/compress audio, the sink will query the chain for information on how to transform its
   * output position to map it onto a media position, via {@link #getMediaDuration(long)} and {@link
   * #getSkippedOutputFrameCount()}.
   */
  public interface AudioProcessorChain {

    /**
     * Returns the fixed chain of audio processors that will process audio. This method is called
     * once during initialization, but audio processors may change state to become active/inactive
     * during playback.
     */
    AudioProcessor[] getAudioProcessors();

    /**
     * Configures audio processors to apply the specified playback parameters immediately, returning
     * the new parameters, which may differ from those passed in. Only called when processors have
     * no input pending.
     *
     * @param playbackParameters The playback parameters to try to apply.
     * @return The playback parameters that were actually applied.
     */
    PlaybackParameters applyPlaybackParameters(PlaybackParameters playbackParameters);

    /**
     * Scales the specified playout duration to take into account speedup due to audio processing,
     * returning an input media duration, in arbitrary units.
     */
    long getMediaDuration(long playoutDuration);

    /**
     * Returns the number of output audio frames skipped since the audio processors were last
     * flushed.
     */
    long getSkippedOutputFrameCount();
  }

  /**
   * The default audio processor chain, which applies a (possibly empty) chain of user-defined audio
   * processors followed by {@link SilenceSkippingAudioProcessor} and {@link SonicAudioProcessor}.
   */
  public static class DefaultAudioProcessorChain implements AudioProcessorChain {

    private final AudioProcessor[] audioProcessors;
    private final SilenceSkippingAudioProcessor silenceSkippingAudioProcessor;
    private final SonicAudioProcessor sonicAudioProcessor;

    /**
     * Creates a new default chain of audio processors, with the user-defined {@code
     * audioProcessors} applied before silence skipping and playback parameters.
     */
    public DefaultAudioProcessorChain(AudioProcessor... audioProcessors) {
      this.audioProcessors = Arrays.copyOf(audioProcessors, audioProcessors.length + 2);
      silenceSkippingAudioProcessor = new SilenceSkippingAudioProcessor();
      sonicAudioProcessor = new SonicAudioProcessor();
      this.audioProcessors[audioProcessors.length] = silenceSkippingAudioProcessor;
      this.audioProcessors[audioProcessors.length + 1] = sonicAudioProcessor;
    }

    @Override
    public AudioProcessor[] getAudioProcessors() {
      return audioProcessors;
    }

    @Override
    public PlaybackParameters applyPlaybackParameters(PlaybackParameters playbackParameters) {
      silenceSkippingAudioProcessor.setEnabled(playbackParameters.skipSilence);
      return new PlaybackParameters(
          sonicAudioProcessor.setSpeed(playbackParameters.speed),
          sonicAudioProcessor.setPitch(playbackParameters.pitch),
          playbackParameters.skipSilence);
    }

    @Override
    public long getMediaDuration(long playoutDuration) {
      return sonicAudioProcessor.scaleDurationForSpeedup(playoutDuration);
    }

    @Override
    public long getSkippedOutputFrameCount() {
      return silenceSkippingAudioProcessor.getSkippedFrames();
    }
  }

  /**
   * A minimum length for the {@link AudioTrack} buffer, in microseconds.
   */
  private static final long MIN_BUFFER_DURATION_US = 250000;
  /**
   * A maximum length for the {@link AudioTrack} buffer, in microseconds.
   */
  private static final long MAX_BUFFER_DURATION_US = 750000;
  /**
   * The length for passthrough {@link AudioTrack} buffers, in microseconds.
   */
  private static final long PASSTHROUGH_BUFFER_DURATION_US = 250000;
  /**
   * A multiplication factor to apply to the minimum buffer size requested by the underlying
   * {@link AudioTrack}.
   */
  private static final int BUFFER_MULTIPLICATION_FACTOR = 4;

  /**
   * @see AudioTrack#ERROR_BAD_VALUE
   */
  private static final int ERROR_BAD_VALUE = AudioTrack.ERROR_BAD_VALUE;
  /**
   * @see AudioTrack#MODE_STATIC
   */
  private static final int MODE_STATIC = AudioTrack.MODE_STATIC;
  /**
   * @see AudioTrack#MODE_STREAM
   */
  private static final int MODE_STREAM = AudioTrack.MODE_STREAM;
  /**
   * @see AudioTrack#STATE_INITIALIZED
   */
  private static final int STATE_INITIALIZED = AudioTrack.STATE_INITIALIZED;
  /**
   * @see AudioTrack#WRITE_NON_BLOCKING
   */
  @SuppressLint("InlinedApi")
  private static final int WRITE_NON_BLOCKING = AudioTrack.WRITE_NON_BLOCKING;

  private static final String TAG = "AudioTrack";

  /**
   * Represents states of the {@link #startMediaTimeUs} value.
   */
  @Retention(RetentionPolicy.SOURCE)
  @IntDef({START_NOT_SET, START_IN_SYNC, START_NEED_SYNC})
  private @interface StartMediaTimeState {}
  private static final int START_NOT_SET = 0;
  private static final int START_IN_SYNC = 1;
  private static final int START_NEED_SYNC = 2;

  /**
   * Whether to enable a workaround for an issue where an audio effect does not keep its session
   * active across releasing/initializing a new audio track, on platform builds where
   * {@link Util#SDK_INT} &lt; 21.
   * <p>
   * The flag must be set before creating a player.
   */
  public static boolean enablePreV21AudioSessionWorkaround = false;

  /**
   * Whether to throw an {@link InvalidAudioTrackTimestampException} when a spurious timestamp is
   * reported from {@link AudioTrack#getTimestamp}.
   * <p>
   * The flag must be set before creating a player. Should be set to {@code true} for testing and
   * debugging purposes only.
   */
  public static boolean failOnSpuriousAudioTimestamp = false;

  @Nullable
  private final AudioCapabilities audioCapabilities;
  private final AudioProcessorChain audioProcessorChain;
  private final boolean enableConvertHighResIntPcmToFloat;
  private final ChannelMappingAudioProcessor channelMappingAudioProcessor;
  private final TrimmingAudioProcessor trimmingAudioProcessor;
  private final AudioProcessor[] toIntPcmAvailableAudioProcessors;
  private final AudioProcessor[] toFloatPcmAvailableAudioProcessors;
  private final ConditionVariable releasingConditionVariable;
  private final AudioTrackPositionTracker audioTrackPositionTracker;
  private final ArrayDeque<PlaybackParametersCheckpoint> playbackParametersCheckpoints;

  @Nullable private Listener listener;
  /** Used to keep the audio session active on pre-V21 builds (see {@link #initialize()}). */
  @Nullable private AudioTrack keepSessionIdAudioTrack;

  private AudioTrack audioTrack;
  private boolean isInputPcm;
  private boolean shouldConvertHighResIntPcmToFloat;
  private int inputSampleRate;
  private int outputSampleRate;
  private int outputChannelConfig;
  private @C.Encoding int outputEncoding;
  private AudioAttributes audioAttributes;
  private boolean processingEnabled;
  private boolean canApplyPlaybackParameters;
  private int bufferSize;

  @Nullable private PlaybackParameters afterDrainPlaybackParameters;
  private PlaybackParameters playbackParameters;
  private long playbackParametersOffsetUs;
  private long playbackParametersPositionUs;

  @Nullable private ByteBuffer avSyncHeader;
  private int bytesUntilNextAvSync;

  private int pcmFrameSize;
  private long submittedPcmBytes;
  private long submittedEncodedFrames;
  private int outputPcmFrameSize;
  private long writtenPcmBytes;
  private long writtenEncodedFrames;
  private int framesPerEncodedSample;
  private @StartMediaTimeState int startMediaTimeState;
  private long startMediaTimeUs;
  private float volume;

  private AudioProcessor[] activeAudioProcessors;
  private ByteBuffer[] outputBuffers;
  @Nullable private ByteBuffer inputBuffer;
  @Nullable private ByteBuffer outputBuffer;
  private byte[] preV21OutputBuffer;
  private int preV21OutputBufferOffset;
  private int drainingAudioProcessorIndex;
  private boolean handledEndOfStream;

  private boolean playing;
  private int audioSessionId;
  private boolean tunneling;
  private long lastFeedElapsedRealtimeMs;

  /**
   * Creates a new default audio sink.
   *
   * @param audioCapabilities The audio capabilities for playback on this device. May be null if the
   *     default capabilities (no encoded audio passthrough support) should be assumed.
   * @param audioProcessors An array of {@link AudioProcessor}s that will process PCM audio before
   *     output. May be empty.
   */
  public DefaultAudioSink(
      @Nullable AudioCapabilities audioCapabilities, AudioProcessor[] audioProcessors) {
    this(audioCapabilities, audioProcessors, /* enableConvertHighResIntPcmToFloat= */ false);
  }

  /**
   * Creates a new default audio sink, optionally using float output for high resolution PCM.
   *
   * @param audioCapabilities The audio capabilities for playback on this device. May be null if the
   *     default capabilities (no encoded audio passthrough support) should be assumed.
   * @param audioProcessors An array of {@link AudioProcessor}s that will process PCM audio before
   *     output. May be empty.
   * @param enableConvertHighResIntPcmToFloat Whether to enable conversion of high resolution
   *     integer PCM to 32-bit float for output, if possible. Functionality that uses 16-bit integer
   *     audio processing (for example, speed and pitch adjustment) will not be available when float
   *     output is in use.
   */
  public DefaultAudioSink(
      @Nullable AudioCapabilities audioCapabilities,
      AudioProcessor[] audioProcessors,
      boolean enableConvertHighResIntPcmToFloat) {
    this(
        audioCapabilities,
        new DefaultAudioProcessorChain(audioProcessors),
        enableConvertHighResIntPcmToFloat);
  }

  /**
   * Creates a new default audio sink, optionally using float output for high resolution PCM and
   * with the specified {@code audioProcessorChain}.
   *
   * @param audioCapabilities The audio capabilities for playback on this device. May be null if the
   *     default capabilities (no encoded audio passthrough support) should be assumed.
   * @param audioProcessorChain An {@link AudioProcessorChain} which is used to apply playback
   *     parameters adjustments. The instance passed in must not be reused in other sinks.
   * @param enableConvertHighResIntPcmToFloat Whether to enable conversion of high resolution
   *     integer PCM to 32-bit float for output, if possible. Functionality that uses 16-bit integer
   *     audio processing (for example, speed and pitch adjustment) will not be available when float
   *     output is in use.
   */
  public DefaultAudioSink(
      @Nullable AudioCapabilities audioCapabilities,
      AudioProcessorChain audioProcessorChain,
      boolean enableConvertHighResIntPcmToFloat) {
    this.audioCapabilities = audioCapabilities;
    this.audioProcessorChain = Assertions.checkNotNull(audioProcessorChain);
    this.enableConvertHighResIntPcmToFloat = enableConvertHighResIntPcmToFloat;
    releasingConditionVariable = new ConditionVariable(true);
    audioTrackPositionTracker = new AudioTrackPositionTracker(new PositionTrackerListener());
    channelMappingAudioProcessor = new ChannelMappingAudioProcessor();
    trimmingAudioProcessor = new TrimmingAudioProcessor();
    ArrayList<AudioProcessor> toIntPcmAudioProcessors = new ArrayList<>();
    Collections.addAll(
        toIntPcmAudioProcessors,
        new ResamplingAudioProcessor(),
        channelMappingAudioProcessor,
        trimmingAudioProcessor);
    Collections.addAll(toIntPcmAudioProcessors, audioProcessorChain.getAudioProcessors());
    toIntPcmAvailableAudioProcessors =
        toIntPcmAudioProcessors.toArray(new AudioProcessor[toIntPcmAudioProcessors.size()]);
    toFloatPcmAvailableAudioProcessors = new AudioProcessor[] {new FloatResamplingAudioProcessor()};
    volume = 1.0f;
    startMediaTimeState = START_NOT_SET;
    audioAttributes = AudioAttributes.DEFAULT;
    audioSessionId = C.AUDIO_SESSION_ID_UNSET;
    playbackParameters = PlaybackParameters.DEFAULT;
    drainingAudioProcessorIndex = C.INDEX_UNSET;
    activeAudioProcessors = new AudioProcessor[0];
    outputBuffers = new ByteBuffer[0];
    playbackParametersCheckpoints = new ArrayDeque<>();
  }

  // AudioSink implementation.

  @Override
  public void setListener(Listener listener) {
    this.listener = listener;
  }

  @Override
  public boolean isEncodingSupported(@C.Encoding int encoding) {
    if (Util.isEncodingPcm(encoding)) {
      // AudioTrack supports 16-bit integer PCM output in all platform API versions, and float
      // output from platform API version 21 only. Other integer PCM encodings are resampled by this
      // sink to 16-bit PCM.
      return encoding != C.ENCODING_PCM_FLOAT || Util.SDK_INT >= 21;
    } else {
      return audioCapabilities != null && audioCapabilities.supportsEncoding(encoding);
    }
  }

  @Override
  public long getCurrentPositionUs(boolean sourceEnded) {
    if (!isInitialized() || startMediaTimeState == START_NOT_SET) {
      return CURRENT_POSITION_NOT_SET;
    }
    long positionUs = audioTrackPositionTracker.getCurrentPositionUs(sourceEnded);
    positionUs = Math.min(positionUs, framesToDurationUs(getWrittenFrames()));
    return startMediaTimeUs + applySkipping(applySpeedup(positionUs));
  }

  @Override
  public void configure(
      @C.Encoding int inputEncoding,
      int inputChannelCount,
      int inputSampleRate,
      int specifiedBufferSize,
      @Nullable int[] outputChannels,
      int trimStartFrames,
      int trimEndFrames)
      throws ConfigurationException {
    boolean flush = false;
    this.inputSampleRate = inputSampleRate;
    int channelCount = inputChannelCount;
    int sampleRate = inputSampleRate;
    isInputPcm = Util.isEncodingPcm(inputEncoding);
    shouldConvertHighResIntPcmToFloat =
        enableConvertHighResIntPcmToFloat
            && isEncodingSupported(C.ENCODING_PCM_32BIT)
            && Util.isEncodingHighResolutionIntegerPcm(inputEncoding);
    if (isInputPcm) {
      pcmFrameSize = Util.getPcmFrameSize(inputEncoding, channelCount);
    }
    @C.Encoding int encoding = inputEncoding;
    boolean processingEnabled = isInputPcm && inputEncoding != C.ENCODING_PCM_FLOAT;
    canApplyPlaybackParameters = processingEnabled && !shouldConvertHighResIntPcmToFloat;
    if (processingEnabled) {
      trimmingAudioProcessor.setTrimFrameCount(trimStartFrames, trimEndFrames);
      channelMappingAudioProcessor.setChannelMap(outputChannels);
      for (AudioProcessor audioProcessor : getAvailableAudioProcessors()) {
        try {
          flush |= audioProcessor.configure(sampleRate, channelCount, encoding);
        } catch (AudioProcessor.UnhandledFormatException e) {
          throw new ConfigurationException(e);
        }
        if (audioProcessor.isActive()) {
          channelCount = audioProcessor.getOutputChannelCount();
          sampleRate = audioProcessor.getOutputSampleRateHz();
          encoding = audioProcessor.getOutputEncoding();
        }
      }
    }

    int channelConfig;
    switch (channelCount) {
      case 1:
        channelConfig = AudioFormat.CHANNEL_OUT_MONO;
        break;
      case 2:
        channelConfig = AudioFormat.CHANNEL_OUT_STEREO;
        break;
      case 3:
        channelConfig = AudioFormat.CHANNEL_OUT_STEREO | AudioFormat.CHANNEL_OUT_FRONT_CENTER;
        break;
      case 4:
        channelConfig = AudioFormat.CHANNEL_OUT_QUAD;
        break;
      case 5:
        channelConfig = AudioFormat.CHANNEL_OUT_QUAD | AudioFormat.CHANNEL_OUT_FRONT_CENTER;
        break;
      case 6:
        channelConfig = AudioFormat.CHANNEL_OUT_5POINT1;
        break;
      case 7:
        channelConfig = AudioFormat.CHANNEL_OUT_5POINT1 | AudioFormat.CHANNEL_OUT_BACK_CENTER;
        break;
      case 8:
        channelConfig = C.CHANNEL_OUT_7POINT1_SURROUND;
        break;
      default:
        throw new ConfigurationException("Unsupported channel count: " + channelCount);
    }

    // Workaround for overly strict channel configuration checks on nVidia Shield.
    if (Util.SDK_INT <= 23 && "foster".equals(Util.DEVICE) && "NVIDIA".equals(Util.MANUFACTURER)) {
      switch (channelCount) {
        case 7:
          channelConfig = C.CHANNEL_OUT_7POINT1_SURROUND;
          break;
        case 3:
        case 5:
          channelConfig = AudioFormat.CHANNEL_OUT_5POINT1;
          break;
        default:
          break;
      }
    }

    // Workaround for Nexus Player not reporting support for mono passthrough.
    // (See [Internal: b/34268671].)
    if (Util.SDK_INT <= 25 && "fugu".equals(Util.DEVICE) && !isInputPcm && channelCount == 1) {
      channelConfig = AudioFormat.CHANNEL_OUT_STEREO;
    }

    if (!flush
        && isInitialized()
        && outputEncoding == encoding
        && outputSampleRate == sampleRate
        && outputChannelConfig == channelConfig) {
      // We already have an audio track with the correct sample rate, channel config and encoding.
      return;
    }

    reset();

    this.processingEnabled = processingEnabled;
    outputSampleRate = sampleRate;
    outputChannelConfig = channelConfig;
    outputEncoding = encoding;
    outputPcmFrameSize =
        isInputPcm ? Util.getPcmFrameSize(outputEncoding, channelCount) : C.LENGTH_UNSET;
    if (specifiedBufferSize != 0) {
      bufferSize = specifiedBufferSize;
    } else if (isInputPcm) {
      int minBufferSize = AudioTrack.getMinBufferSize(sampleRate, channelConfig, outputEncoding);
      Assertions.checkState(minBufferSize != ERROR_BAD_VALUE);
      int multipliedBufferSize = minBufferSize * BUFFER_MULTIPLICATION_FACTOR;
      int minAppBufferSize = (int) durationUsToFrames(MIN_BUFFER_DURATION_US) * outputPcmFrameSize;
      int maxAppBufferSize = (int) Math.max(minBufferSize,
          durationUsToFrames(MAX_BUFFER_DURATION_US) * outputPcmFrameSize);
      bufferSize = Util.constrainValue(multipliedBufferSize, minAppBufferSize, maxAppBufferSize);
    } else {
      // TODO: Set the minimum buffer size using getMinBufferSize when it takes the encoding into
      // account. [Internal: b/25181305]
      if (outputEncoding == C.ENCODING_AC3 || outputEncoding == C.ENCODING_E_AC3) {
        // AC-3 allows bitrates up to 640 kbit/s.
        bufferSize = (int) (PASSTHROUGH_BUFFER_DURATION_US * 80 * 1024 / C.MICROS_PER_SECOND);
      } else if (outputEncoding == C.ENCODING_DTS) {
        // DTS allows an 'open' bitrate, but we assume the maximum listed value: 1536 kbit/s.
        bufferSize = (int) (PASSTHROUGH_BUFFER_DURATION_US * 192 * 1024 / C.MICROS_PER_SECOND);
      } else /* outputEncoding == C.ENCODING_DTS_HD || outputEncoding == C.ENCODING_DOLBY_TRUEHD*/ {
        // HD passthrough requires a larger buffer to avoid underrun.
        bufferSize = (int) (PASSTHROUGH_BUFFER_DURATION_US * 192 * 6 * 1024 / C.MICROS_PER_SECOND);
      }
    }
  }

  private void setupAudioProcessors() {
    ArrayList<AudioProcessor> newAudioProcessors = new ArrayList<>();
    for (AudioProcessor audioProcessor : getAvailableAudioProcessors()) {
      if (audioProcessor.isActive()) {
        newAudioProcessors.add(audioProcessor);
      } else {
        audioProcessor.flush();
      }
    }
    int count = newAudioProcessors.size();
    activeAudioProcessors = newAudioProcessors.toArray(new AudioProcessor[count]);
    outputBuffers = new ByteBuffer[count];
    flushAudioProcessors();
  }

  private void flushAudioProcessors() {
    for (int i = 0; i < activeAudioProcessors.length; i++) {
      AudioProcessor audioProcessor = activeAudioProcessors[i];
      audioProcessor.flush();
      outputBuffers[i] = audioProcessor.getOutput();
    }
  }

  private void initialize() throws InitializationException {
    // If we're asynchronously releasing a previous audio track then we block until it has been
    // released. This guarantees that we cannot end up in a state where we have multiple audio
    // track instances. Without this guarantee it would be possible, in extreme cases, to exhaust
    // the shared memory that's available for audio track buffers. This would in turn cause the
    // initialization of the audio track to fail.
    releasingConditionVariable.block();

    audioTrack = initializeAudioTrack();
    int audioSessionId = audioTrack.getAudioSessionId();
    if (enablePreV21AudioSessionWorkaround) {
      if (Util.SDK_INT < 21) {
        // The workaround creates an audio track with a two byte buffer on the same session, and
        // does not release it until this object is released, which keeps the session active.
        if (keepSessionIdAudioTrack != null
            && audioSessionId != keepSessionIdAudioTrack.getAudioSessionId()) {
          releaseKeepSessionIdAudioTrack();
        }
        if (keepSessionIdAudioTrack == null) {
          keepSessionIdAudioTrack = initializeKeepSessionIdAudioTrack(audioSessionId);
        }
      }
    }
    if (this.audioSessionId != audioSessionId) {
      this.audioSessionId = audioSessionId;
      if (listener != null) {
        listener.onAudioSessionId(audioSessionId);
      }
    }

    playbackParameters =
        canApplyPlaybackParameters
            ? audioProcessorChain.applyPlaybackParameters(playbackParameters)
            : PlaybackParameters.DEFAULT;
    setupAudioProcessors();

    audioTrackPositionTracker.setAudioTrack(
        audioTrack, outputEncoding, outputPcmFrameSize, bufferSize);
    setVolumeInternal();
  }

  @Override
  public void play() {
    playing = true;
    if (isInitialized()) {
      audioTrackPositionTracker.start();
      audioTrack.play();
    }
  }

  @Override
  public void handleDiscontinuity() {
    // Force resynchronization after a skipped buffer.
    if (startMediaTimeState == START_IN_SYNC) {
      startMediaTimeState = START_NEED_SYNC;
    }
  }

  @Override
  @SuppressWarnings("ReferenceEquality")
  public boolean handleBuffer(ByteBuffer buffer, long presentationTimeUs)
      throws InitializationException, WriteException {
    Assertions.checkArgument(inputBuffer == null || buffer == inputBuffer);
    if (!isInitialized()) {
      initialize();
      if (playing) {
        play();
      }
    }

    if (!audioTrackPositionTracker.mayHandleBuffer(getWrittenFrames())) {
      return false;
    }

    if (inputBuffer == null) {
      // We are seeing this buffer for the first time.
      if (!buffer.hasRemaining()) {
        // The buffer is empty.
        return true;
      }

      if (!isInputPcm && framesPerEncodedSample == 0) {
        // If this is the first encoded sample, calculate the sample size in frames.
        framesPerEncodedSample = getFramesPerEncodedSample(outputEncoding, buffer);
        if (framesPerEncodedSample == 0) {
          // We still don't know the number of frames per sample, so drop the buffer.
          // For TrueHD this can occur after some seek operations, as not every sample starts with
          // a syncframe header. If we chunked samples together so the extracted samples always
          // started with a syncframe header, the chunks would be too large.
          return true;
        }
      }

      if (afterDrainPlaybackParameters != null) {
        if (!drainAudioProcessorsToEndOfStream()) {
          // Don't process any more input until draining completes.
          return false;
        }
        PlaybackParameters newPlaybackParameters = afterDrainPlaybackParameters;
        afterDrainPlaybackParameters = null;
        newPlaybackParameters = audioProcessorChain.applyPlaybackParameters(newPlaybackParameters);
        // Store the position and corresponding media time from which the parameters will apply.
        playbackParametersCheckpoints.add(
            new PlaybackParametersCheckpoint(
                newPlaybackParameters,
                Math.max(0, presentationTimeUs),
                framesToDurationUs(getWrittenFrames())));
        // Update the set of active audio processors to take into account the new parameters.
        setupAudioProcessors();
      }

      if (startMediaTimeState == START_NOT_SET) {
        startMediaTimeUs = Math.max(0, presentationTimeUs);
        startMediaTimeState = START_IN_SYNC;
      } else {
        // Sanity check that presentationTimeUs is consistent with the expected value.
        long expectedPresentationTimeUs =
            startMediaTimeUs + inputFramesToDurationUs(getSubmittedFrames());
        if (startMediaTimeState == START_IN_SYNC
            && Math.abs(expectedPresentationTimeUs - presentationTimeUs) > 200000) {
          Log.e(TAG, "Discontinuity detected [expected " + expectedPresentationTimeUs + ", got "
              + presentationTimeUs + "]");
          startMediaTimeState = START_NEED_SYNC;
        }
        if (startMediaTimeState == START_NEED_SYNC) {
          // Adjust startMediaTimeUs to be consistent with the current buffer's start time and the
          // number of bytes submitted.
          startMediaTimeUs += (presentationTimeUs - expectedPresentationTimeUs);
          startMediaTimeState = START_IN_SYNC;
          if (listener != null) {
            listener.onPositionDiscontinuity();
          }
        }
      }

      if (isInputPcm) {
        submittedPcmBytes += buffer.remaining();
      } else {
        submittedEncodedFrames += framesPerEncodedSample;
      }

      inputBuffer = buffer;
    }

    if (processingEnabled) {
      processBuffers(presentationTimeUs);
    } else {
      writeBuffer(inputBuffer, presentationTimeUs);
    }

    if (!inputBuffer.hasRemaining()) {
      inputBuffer = null;
      return true;
    }

    if (audioTrackPositionTracker.isStalled(getWrittenFrames())) {
      Log.w(TAG, "Resetting stalled audio track");
      reset();
      return true;
    }

    return false;
  }

  private void processBuffers(long avSyncPresentationTimeUs) throws WriteException {
    int count = activeAudioProcessors.length;
    int index = count;
    while (index >= 0) {
      ByteBuffer input = index > 0 ? outputBuffers[index - 1]
          : (inputBuffer != null ? inputBuffer : AudioProcessor.EMPTY_BUFFER);
      if (index == count) {
        writeBuffer(input, avSyncPresentationTimeUs);
      } else {
        AudioProcessor audioProcessor = activeAudioProcessors[index];
        audioProcessor.queueInput(input);
        ByteBuffer output = audioProcessor.getOutput();
        outputBuffers[index] = output;
        if (output.hasRemaining()) {
          // Handle the output as input to the next audio processor or the AudioTrack.
          index++;
          continue;
        }
      }

      if (input.hasRemaining()) {
        // The input wasn't consumed and no output was produced, so give up for now.
        return;
      }

      // Get more input from upstream.
      index--;
    }
  }

  @SuppressWarnings("ReferenceEquality")
  private void writeBuffer(ByteBuffer buffer, long avSyncPresentationTimeUs) throws WriteException {
    if (!buffer.hasRemaining()) {
      return;
    }
    if (outputBuffer != null) {
      Assertions.checkArgument(outputBuffer == buffer);
    } else {
      outputBuffer = buffer;
      if (Util.SDK_INT < 21) {
        int bytesRemaining = buffer.remaining();
        if (preV21OutputBuffer == null || preV21OutputBuffer.length < bytesRemaining) {
          preV21OutputBuffer = new byte[bytesRemaining];
        }
        int originalPosition = buffer.position();
        buffer.get(preV21OutputBuffer, 0, bytesRemaining);
        buffer.position(originalPosition);
        preV21OutputBufferOffset = 0;
      }
    }
    int bytesRemaining = buffer.remaining();
    int bytesWritten = 0;
    if (Util.SDK_INT < 21) { // isInputPcm == true
      // Work out how many bytes we can write without the risk of blocking.
      int bytesToWrite = audioTrackPositionTracker.getAvailableBufferSize(writtenPcmBytes);
      if (bytesToWrite > 0) {
        bytesToWrite = Math.min(bytesRemaining, bytesToWrite);
        bytesWritten = audioTrack.write(preV21OutputBuffer, preV21OutputBufferOffset, bytesToWrite);
        if (bytesWritten > 0) {
          preV21OutputBufferOffset += bytesWritten;
          buffer.position(buffer.position() + bytesWritten);
        }
      }
    } else if (tunneling) {
      Assertions.checkState(avSyncPresentationTimeUs != C.TIME_UNSET);
      bytesWritten = writeNonBlockingWithAvSyncV21(audioTrack, buffer, bytesRemaining,
          avSyncPresentationTimeUs);
    } else {
      bytesWritten = writeNonBlockingV21(audioTrack, buffer, bytesRemaining);
    }

    lastFeedElapsedRealtimeMs = SystemClock.elapsedRealtime();

    if (bytesWritten < 0) {
      throw new WriteException(bytesWritten);
    }

    if (isInputPcm) {
      writtenPcmBytes += bytesWritten;
    }
    if (bytesWritten == bytesRemaining) {
      if (!isInputPcm) {
        writtenEncodedFrames += framesPerEncodedSample;
      }
      outputBuffer = null;
    }
  }

  @Override
  public void playToEndOfStream() throws WriteException {
    if (handledEndOfStream || !isInitialized()) {
      return;
    }

    if (drainAudioProcessorsToEndOfStream()) {
      // The audio processors have drained, so drain the underlying audio track.
      audioTrackPositionTracker.handleEndOfStream(getWrittenFrames());
      audioTrack.stop();
      bytesUntilNextAvSync = 0;
      handledEndOfStream = true;
    }
  }

  private boolean drainAudioProcessorsToEndOfStream() throws WriteException {
    boolean audioProcessorNeedsEndOfStream = false;
    if (drainingAudioProcessorIndex == C.INDEX_UNSET) {
      drainingAudioProcessorIndex = processingEnabled ? 0 : activeAudioProcessors.length;
      audioProcessorNeedsEndOfStream = true;
    }
    while (drainingAudioProcessorIndex < activeAudioProcessors.length) {
      AudioProcessor audioProcessor = activeAudioProcessors[drainingAudioProcessorIndex];
      if (audioProcessorNeedsEndOfStream) {
        audioProcessor.queueEndOfStream();
      }
      processBuffers(C.TIME_UNSET);
      if (!audioProcessor.isEnded()) {
        return false;
      }
      audioProcessorNeedsEndOfStream = true;
      drainingAudioProcessorIndex++;
    }

    // Finish writing any remaining output to the track.
    if (outputBuffer != null) {
      writeBuffer(outputBuffer, C.TIME_UNSET);
      if (outputBuffer != null) {
        return false;
      }
    }
    drainingAudioProcessorIndex = C.INDEX_UNSET;
    return true;
  }

  @Override
  public boolean isEnded() {
    return !isInitialized() || (handledEndOfStream && !hasPendingData());
  }

  @Override
  public boolean hasPendingData() {
    return isInitialized() && audioTrackPositionTracker.hasPendingData(getWrittenFrames());
  }

  @Override
  public PlaybackParameters setPlaybackParameters(PlaybackParameters playbackParameters) {
    if (isInitialized() && !canApplyPlaybackParameters) {
      this.playbackParameters = PlaybackParameters.DEFAULT;
      return this.playbackParameters;
    }
    PlaybackParameters lastSetPlaybackParameters =
        afterDrainPlaybackParameters != null
            ? afterDrainPlaybackParameters
            : !playbackParametersCheckpoints.isEmpty()
                ? playbackParametersCheckpoints.getLast().playbackParameters
                : this.playbackParameters;
    if (!playbackParameters.equals(lastSetPlaybackParameters)) {
      if (isInitialized()) {
        // Drain the audio processors so we can determine the frame position at which the new
        // parameters apply.
        afterDrainPlaybackParameters = playbackParameters;
      } else {
        // Update the playback parameters now.
        this.playbackParameters = audioProcessorChain.applyPlaybackParameters(playbackParameters);
      }
    }
    return this.playbackParameters;
  }

  @Override
  public PlaybackParameters getPlaybackParameters() {
    return playbackParameters;
  }

  @Override
  public void setAudioAttributes(AudioAttributes audioAttributes) {
    if (this.audioAttributes.equals(audioAttributes)) {
      return;
    }
    this.audioAttributes = audioAttributes;
    if (tunneling) {
      // The audio attributes are ignored in tunneling mode, so no need to reset.
      return;
    }
    reset();
    audioSessionId = C.AUDIO_SESSION_ID_UNSET;
  }

  @Override
  public void setAudioSessionId(int audioSessionId) {
    if (this.audioSessionId != audioSessionId) {
      this.audioSessionId = audioSessionId;
      reset();
    }
  }

  @Override
  public void enableTunnelingV21(int tunnelingAudioSessionId) {
    Assertions.checkState(Util.SDK_INT >= 21);
    if (!tunneling || audioSessionId != tunnelingAudioSessionId) {
      tunneling = true;
      audioSessionId = tunnelingAudioSessionId;
      reset();
    }
  }

  @Override
  public void disableTunneling() {
    if (tunneling) {
      tunneling = false;
      audioSessionId = C.AUDIO_SESSION_ID_UNSET;
      reset();
    }
  }

  @Override
  public void setVolume(float volume) {
    if (this.volume != volume) {
      this.volume = volume;
      setVolumeInternal();
    }
  }

  private void setVolumeInternal() {
    if (!isInitialized()) {
      // Do nothing.
    } else if (Util.SDK_INT >= 21) {
      setVolumeInternalV21(audioTrack, volume);
    } else {
      setVolumeInternalV3(audioTrack, volume);
    }
  }

  @Override
  public void pause() {
    playing = false;
    if (isInitialized() && audioTrackPositionTracker.pause()) {
      audioTrack.pause();
    }
  }

  @Override
  public void reset() {
    if (isInitialized()) {
      submittedPcmBytes = 0;
      submittedEncodedFrames = 0;
      writtenPcmBytes = 0;
      writtenEncodedFrames = 0;
      framesPerEncodedSample = 0;
      if (afterDrainPlaybackParameters != null) {
        playbackParameters = afterDrainPlaybackParameters;
        afterDrainPlaybackParameters = null;
      } else if (!playbackParametersCheckpoints.isEmpty()) {
        playbackParameters = playbackParametersCheckpoints.getLast().playbackParameters;
      }
      playbackParametersCheckpoints.clear();
      playbackParametersOffsetUs = 0;
      playbackParametersPositionUs = 0;
      inputBuffer = null;
      outputBuffer = null;
      flushAudioProcessors();
      handledEndOfStream = false;
      drainingAudioProcessorIndex = C.INDEX_UNSET;
      avSyncHeader = null;
      bytesUntilNextAvSync = 0;
      startMediaTimeState = START_NOT_SET;
      if (audioTrackPositionTracker.isPlaying()) {
        audioTrack.pause();
      }
      // AudioTrack.release can take some time, so we call it on a background thread.
      final AudioTrack toRelease = audioTrack;
      audioTrack = null;
      audioTrackPositionTracker.reset();
      releasingConditionVariable.close();
      new Thread() {
        @Override
        public void run() {
          try {
            toRelease.flush();
            toRelease.release();
          } finally {
            releasingConditionVariable.open();
          }
        }
      }.start();
    }
  }

  @Override
  public void release() {
    reset();
    releaseKeepSessionIdAudioTrack();
    for (AudioProcessor audioProcessor : toIntPcmAvailableAudioProcessors) {
      audioProcessor.reset();
    }
    for (AudioProcessor audioProcessor : toFloatPcmAvailableAudioProcessors) {
      audioProcessor.reset();
    }
    audioSessionId = C.AUDIO_SESSION_ID_UNSET;
    playing = false;
  }

  /**
   * Releases {@link #keepSessionIdAudioTrack} asynchronously, if it is non-{@code null}.
   */
  private void releaseKeepSessionIdAudioTrack() {
    if (keepSessionIdAudioTrack == null) {
      return;
    }

    // AudioTrack.release can take some time, so we call it on a background thread.
    final AudioTrack toRelease = keepSessionIdAudioTrack;
    keepSessionIdAudioTrack = null;
    new Thread() {
      @Override
      public void run() {
        toRelease.release();
      }
    }.start();
  }

  private long applySpeedup(long positionUs) {
    @Nullable PlaybackParametersCheckpoint checkpoint = null;
    while (!playbackParametersCheckpoints.isEmpty()
        && positionUs >= playbackParametersCheckpoints.getFirst().positionUs) {
      checkpoint = playbackParametersCheckpoints.remove();
    }
    if (checkpoint != null) {
      // We are playing (or about to play) media with the new playback parameters, so update them.
      playbackParameters = checkpoint.playbackParameters;
      playbackParametersPositionUs = checkpoint.positionUs;
      playbackParametersOffsetUs = checkpoint.mediaTimeUs - startMediaTimeUs;
    }

    if (playbackParameters.speed == 1f) {
      return positionUs + playbackParametersOffsetUs - playbackParametersPositionUs;
    }

    if (playbackParametersCheckpoints.isEmpty()) {
      return playbackParametersOffsetUs
          + audioProcessorChain.getMediaDuration(positionUs - playbackParametersPositionUs);
    }

    // We are playing data at a previous playback speed, so fall back to multiplying by the speed.
    return playbackParametersOffsetUs
        + Util.getMediaDurationForPlayoutDuration(
            positionUs - playbackParametersPositionUs, playbackParameters.speed);
  }

  private long applySkipping(long positionUs) {
    return positionUs + framesToDurationUs(audioProcessorChain.getSkippedOutputFrameCount());
  }

  private boolean isInitialized() {
    return audioTrack != null;
  }

  private long inputFramesToDurationUs(long frameCount) {
    return (frameCount * C.MICROS_PER_SECOND) / inputSampleRate;
  }

  private long framesToDurationUs(long frameCount) {
    return (frameCount * C.MICROS_PER_SECOND) / outputSampleRate;
  }

  private long durationUsToFrames(long durationUs) {
    return (durationUs * outputSampleRate) / C.MICROS_PER_SECOND;
  }

  private long getSubmittedFrames() {
    return isInputPcm ? (submittedPcmBytes / pcmFrameSize) : submittedEncodedFrames;
  }

  private long getWrittenFrames() {
    return isInputPcm ? (writtenPcmBytes / outputPcmFrameSize) : writtenEncodedFrames;
  }

  private AudioTrack initializeAudioTrack() throws InitializationException {
    AudioTrack audioTrack;
    if (Util.SDK_INT >= 21) {
      audioTrack = createAudioTrackV21();
    } else {
      int streamType = Util.getStreamTypeForAudioUsage(audioAttributes.usage);
      if (audioSessionId == C.AUDIO_SESSION_ID_UNSET) {
        audioTrack =
            new AudioTrack(
                streamType,
                outputSampleRate,
                outputChannelConfig,
                outputEncoding,
                bufferSize,
                MODE_STREAM);
      } else {
        // Re-attach to the same audio session.
        audioTrack =
            new AudioTrack(
                streamType,
                outputSampleRate,
                outputChannelConfig,
                outputEncoding,
                bufferSize,
                MODE_STREAM,
                audioSessionId);
      }
    }

    int state = audioTrack.getState();
    if (state != STATE_INITIALIZED) {
      try {
        audioTrack.release();
      } catch (Exception e) {
        // The track has already failed to initialize, so it wouldn't be that surprising if release
        // were to fail too. Swallow the exception.
      }
      throw new InitializationException(state, outputSampleRate, outputChannelConfig, bufferSize);
    }
    return audioTrack;
  }

  @TargetApi(21)
  private AudioTrack createAudioTrackV21() {
    android.media.AudioAttributes attributes;
    if (tunneling) {
      attributes = new android.media.AudioAttributes.Builder()
          .setContentType(android.media.AudioAttributes.CONTENT_TYPE_MOVIE)
          .setFlags(android.media.AudioAttributes.FLAG_HW_AV_SYNC)
          .setUsage(android.media.AudioAttributes.USAGE_MEDIA)
          .build();
    } else {
      attributes = audioAttributes.getAudioAttributesV21();
    }
    AudioFormat format =
        new AudioFormat.Builder()
            .setChannelMask(outputChannelConfig)
            .setEncoding(outputEncoding)
            .setSampleRate(outputSampleRate)
            .build();
    int audioSessionId = this.audioSessionId != C.AUDIO_SESSION_ID_UNSET ? this.audioSessionId
        : AudioManager.AUDIO_SESSION_ID_GENERATE;
    return new AudioTrack(attributes, format, bufferSize, MODE_STREAM, audioSessionId);
  }

  private AudioTrack initializeKeepSessionIdAudioTrack(int audioSessionId) {
    int sampleRate = 4000; // Equal to private AudioTrack.MIN_SAMPLE_RATE.
    int channelConfig = AudioFormat.CHANNEL_OUT_MONO;
    @C.PcmEncoding int encoding = C.ENCODING_PCM_16BIT;
    int bufferSize = 2; // Use a two byte buffer, as it is not actually used for playback.
    return new AudioTrack(C.STREAM_TYPE_DEFAULT, sampleRate, channelConfig, encoding, bufferSize,
        MODE_STATIC, audioSessionId);
  }

  private AudioProcessor[] getAvailableAudioProcessors() {
    return shouldConvertHighResIntPcmToFloat
        ? toFloatPcmAvailableAudioProcessors
        : toIntPcmAvailableAudioProcessors;
  }

  private static int getFramesPerEncodedSample(@C.Encoding int encoding, ByteBuffer buffer) {
    if (encoding == C.ENCODING_DTS || encoding == C.ENCODING_DTS_HD) {
      return DtsUtil.parseDtsAudioSampleCount(buffer);
    } else if (encoding == C.ENCODING_AC3) {
      return Ac3Util.getAc3SyncframeAudioSampleCount();
    } else if (encoding == C.ENCODING_E_AC3) {
      return Ac3Util.parseEAc3SyncframeAudioSampleCount(buffer);
    } else if (encoding == C.ENCODING_DOLBY_TRUEHD) {
      int syncframeOffset = Ac3Util.findTrueHdSyncframeOffset(buffer);
      return syncframeOffset == C.INDEX_UNSET
          ? 0
          : (Ac3Util.parseTrueHdSyncframeAudioSampleCount(buffer, syncframeOffset)
              * Ac3Util.TRUEHD_RECHUNK_SAMPLE_COUNT);
    } else {
      throw new IllegalStateException("Unexpected audio encoding: " + encoding);
    }
  }

  @TargetApi(21)
  private static int writeNonBlockingV21(AudioTrack audioTrack, ByteBuffer buffer, int size) {
    return audioTrack.write(buffer, size, WRITE_NON_BLOCKING);
  }

  @TargetApi(21)
  private int writeNonBlockingWithAvSyncV21(AudioTrack audioTrack, ByteBuffer buffer, int size,
      long presentationTimeUs) {
    // TODO: Uncomment this when [Internal ref: b/33627517] is clarified or fixed.
    // if (Util.SDK_INT >= 23) {
    //   // The underlying platform AudioTrack writes AV sync headers directly.
    //   return audioTrack.write(buffer, size, WRITE_NON_BLOCKING, presentationTimeUs * 1000);
    // }
    if (avSyncHeader == null) {
      avSyncHeader = ByteBuffer.allocate(16);
      avSyncHeader.order(ByteOrder.BIG_ENDIAN);
      avSyncHeader.putInt(0x55550001);
    }
    if (bytesUntilNextAvSync == 0) {
      avSyncHeader.putInt(4, size);
      avSyncHeader.putLong(8, presentationTimeUs * 1000);
      avSyncHeader.position(0);
      bytesUntilNextAvSync = size;
    }
    int avSyncHeaderBytesRemaining = avSyncHeader.remaining();
    if (avSyncHeaderBytesRemaining > 0) {
      int result = audioTrack.write(avSyncHeader, avSyncHeaderBytesRemaining, WRITE_NON_BLOCKING);
      if (result < 0) {
        bytesUntilNextAvSync = 0;
        return result;
      }
      if (result < avSyncHeaderBytesRemaining) {
        return 0;
      }
    }
    int result = writeNonBlockingV21(audioTrack, buffer, size);
    if (result < 0) {
      bytesUntilNextAvSync = 0;
      return result;
    }
    bytesUntilNextAvSync -= result;
    return result;
  }

  @TargetApi(21)
  private static void setVolumeInternalV21(AudioTrack audioTrack, float volume) {
    audioTrack.setVolume(volume);
  }

  @SuppressWarnings("deprecation")
  private static void setVolumeInternalV3(AudioTrack audioTrack, float volume) {
    audioTrack.setStereoVolume(volume, volume);
  }

  /**
   * Stores playback parameters with the position and media time at which they apply.
   */
  private static final class PlaybackParametersCheckpoint {

    private final PlaybackParameters playbackParameters;
    private final long mediaTimeUs;
    private final long positionUs;

    private PlaybackParametersCheckpoint(PlaybackParameters playbackParameters, long mediaTimeUs,
        long positionUs) {
      this.playbackParameters = playbackParameters;
      this.mediaTimeUs = mediaTimeUs;
      this.positionUs = positionUs;
    }

  }

  private final class PositionTrackerListener implements AudioTrackPositionTracker.Listener {

    @Override
    public void onPositionFramesMismatch(
        long audioTimestampPositionFrames,
        long audioTimestampSystemTimeUs,
        long systemTimeUs,
        long playbackPositionUs) {
      String message =
          "Spurious audio timestamp (frame position mismatch): "
              + audioTimestampPositionFrames
              + ", "
              + audioTimestampSystemTimeUs
              + ", "
              + systemTimeUs
              + ", "
              + playbackPositionUs
              + ", "
              + getSubmittedFrames()
              + ", "
              + getWrittenFrames();
      if (failOnSpuriousAudioTimestamp) {
        throw new InvalidAudioTrackTimestampException(message);
      }
      Log.w(TAG, message);
    }

    @Override
    public void onSystemTimeUsMismatch(
        long audioTimestampPositionFrames,
        long audioTimestampSystemTimeUs,
        long systemTimeUs,
        long playbackPositionUs) {
      String message =
          "Spurious audio timestamp (system clock mismatch): "
              + audioTimestampPositionFrames
              + ", "
              + audioTimestampSystemTimeUs
              + ", "
              + systemTimeUs
              + ", "
              + playbackPositionUs
              + ", "
              + getSubmittedFrames()
              + ", "
              + getWrittenFrames();
      if (failOnSpuriousAudioTimestamp) {
        throw new InvalidAudioTrackTimestampException(message);
      }
      Log.w(TAG, message);
    }

    @Override
    public void onInvalidLatency(long latencyUs) {
      Log.w(TAG, "Ignoring impossibly large audio latency: " + latencyUs);
    }

    @Override
    public void onUnderrun(int bufferSize, long bufferSizeMs) {
      if (listener != null) {
        long elapsedSinceLastFeedMs = SystemClock.elapsedRealtime() - lastFeedElapsedRealtimeMs;
        listener.onUnderrun(bufferSize, bufferSizeMs, elapsedSinceLastFeedMs);
      }
    }
  }
}
