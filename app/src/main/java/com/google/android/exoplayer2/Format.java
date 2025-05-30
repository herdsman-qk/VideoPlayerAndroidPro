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

import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.Nullable;

import com.google.android.exoplayer2.drm.DrmInitData;
import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.util.MimeTypes;
import com.google.android.exoplayer2.util.Util;
import com.google.android.exoplayer2.video.ColorInfo;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Representation of a media format.
 */
public final class Format implements Parcelable {

  /**
   * A value for various fields to indicate that the field's value is unknown or not applicable.
   */
  public static final int NO_VALUE = -1;

  /**
   * A value for {@link #subsampleOffsetUs} to indicate that subsample timestamps are relative to
   * the timestamps of their parent samples.
   */
  public static final long OFFSET_SAMPLE_RELATIVE = Long.MAX_VALUE;

  /** An identifier for the format, or null if unknown or not applicable. */
  public final @Nullable String id;
  /**
   * The average bandwidth in bits per second, or {@link #NO_VALUE} if unknown or not applicable.
   */
  public final int bitrate;
  /** Codecs of the format as described in RFC 6381, or null if unknown or not applicable. */
  public final @Nullable String codecs;
  /** Metadata, or null if unknown or not applicable. */
  public final @Nullable Metadata metadata;

  // Container specific.

  /** The mime type of the container, or null if unknown or not applicable. */
  public final @Nullable String containerMimeType;

  // Elementary stream specific.

  /**
   * The mime type of the elementary stream (i.e. the individual samples), or null if unknown or not
   * applicable.
   */
  public final @Nullable String sampleMimeType;
  /**
   * The maximum size of a buffer of data (typically one sample), or {@link #NO_VALUE} if unknown or
   * not applicable.
   */
  public final int maxInputSize;
  /**
   * Initialization data that must be provided to the decoder. Will not be null, but may be empty
   * if initialization data is not required.
   */
  public final List<byte[]> initializationData;
  /** DRM initialization data if the stream is protected, or null otherwise. */
  public final @Nullable DrmInitData drmInitData;

  // Video specific.

  /**
   * The width of the video in pixels, or {@link #NO_VALUE} if unknown or not applicable.
   */
  public final int width;
  /**
   * The height of the video in pixels, or {@link #NO_VALUE} if unknown or not applicable.
   */
  public final int height;
  /**
   * The frame rate in frames per second, or {@link #NO_VALUE} if unknown or not applicable.
   */
  public final float frameRate;
  /**
   * The clockwise rotation that should be applied to the video for it to be rendered in the correct
   * orientation, or 0 if unknown or not applicable. Only 0, 90, 180 and 270 are supported.
   */
  public final int rotationDegrees;
  /** The width to height ratio of pixels in the video, or 1.0 if unknown or not applicable. */
  public final float pixelWidthHeightRatio;
  /**
   * The stereo layout for 360/3D/VR video, or {@link #NO_VALUE} if not applicable. Valid stereo
   * modes are {@link C#STEREO_MODE_MONO}, {@link C#STEREO_MODE_TOP_BOTTOM}, {@link
   * C#STEREO_MODE_LEFT_RIGHT}, {@link C#STEREO_MODE_STEREO_MESH}.
   */
  @C.StereoMode
  public final int stereoMode;
  /** The projection data for 360/VR video, or null if not applicable. */
  public final @Nullable byte[] projectionData;
  /** The color metadata associated with the video, helps with accurate color reproduction. */
  public final @Nullable ColorInfo colorInfo;

  // Audio specific.

  /**
   * The number of audio channels, or {@link #NO_VALUE} if unknown or not applicable.
   */
  public final int channelCount;
  /**
   * The audio sampling rate in Hz, or {@link #NO_VALUE} if unknown or not applicable.
   */
  public final int sampleRate;
  /**
   * The encoding for PCM audio streams. If {@link #sampleMimeType} is {@link MimeTypes#AUDIO_RAW}
   * then one of {@link C#ENCODING_PCM_8BIT}, {@link C#ENCODING_PCM_16BIT},
   * {@link C#ENCODING_PCM_24BIT} and {@link C#ENCODING_PCM_32BIT}. Set to {@link #NO_VALUE} for
   * other media types.
   */
  @C.PcmEncoding
  public final int pcmEncoding;
  /**
   * The number of frames to trim from the start of the decoded audio stream, or 0 if not
   * applicable.
   */
  public final int encoderDelay;
  /**
   * The number of frames to trim from the end of the decoded audio stream, or 0 if not applicable.
   */
  public final int encoderPadding;

  // Text specific.

  /**
   * For samples that contain subsamples, this is an offset that should be added to subsample
   * timestamps. A value of {@link #OFFSET_SAMPLE_RELATIVE} indicates that subsample timestamps are
   * relative to the timestamps of their parent samples.
   */
  public final long subsampleOffsetUs;

  // Audio and text specific.

  /**
   * Track selection flags.
   */
  @C.SelectionFlags
  public final int selectionFlags;

  /** The language, or null if unknown or not applicable. */
  public final @Nullable String language;

  /**
   * The Accessibility channel, or {@link #NO_VALUE} if not known or applicable.
   */
  public final int accessibilityChannel;

  // Lazily initialized hashcode.
  private int hashCode;

  // Video.

  public static Format createVideoContainerFormat(
      @Nullable String id,
      @Nullable String containerMimeType,
      String sampleMimeType,
      String codecs,
      int bitrate,
      int width,
      int height,
      float frameRate,
      List<byte[]> initializationData,
      @C.SelectionFlags int selectionFlags) {
    return new Format(id, containerMimeType, sampleMimeType, codecs, bitrate, NO_VALUE, width,
        height, frameRate, NO_VALUE, NO_VALUE, null, NO_VALUE, null, NO_VALUE, NO_VALUE, NO_VALUE,
        NO_VALUE, NO_VALUE, selectionFlags, null, NO_VALUE, OFFSET_SAMPLE_RELATIVE,
        initializationData, null, null);
  }

  public static Format createVideoSampleFormat(
      @Nullable String id,
      @Nullable String sampleMimeType,
      @Nullable String codecs,
      int bitrate,
      int maxInputSize,
      int width,
      int height,
      float frameRate,
      List<byte[]> initializationData,
      @Nullable DrmInitData drmInitData) {
    return createVideoSampleFormat(id, sampleMimeType, codecs, bitrate, maxInputSize, width,
        height, frameRate, initializationData, NO_VALUE, NO_VALUE, drmInitData);
  }

  public static Format createVideoSampleFormat(
      @Nullable String id,
      @Nullable String sampleMimeType,
      @Nullable String codecs,
      int bitrate,
      int maxInputSize,
      int width,
      int height,
      float frameRate,
      List<byte[]> initializationData,
      int rotationDegrees,
      float pixelWidthHeightRatio,
      @Nullable DrmInitData drmInitData) {
    return createVideoSampleFormat(id, sampleMimeType, codecs, bitrate, maxInputSize, width,
        height, frameRate, initializationData, rotationDegrees, pixelWidthHeightRatio, null,
        NO_VALUE, null, drmInitData);
  }

  public static Format createVideoSampleFormat(
      @Nullable String id,
      @Nullable String sampleMimeType,
      @Nullable String codecs,
      int bitrate,
      int maxInputSize,
      int width,
      int height,
      float frameRate,
      List<byte[]> initializationData,
      int rotationDegrees,
      float pixelWidthHeightRatio,
      byte[] projectionData,
      @C.StereoMode int stereoMode,
      @Nullable ColorInfo colorInfo,
      @Nullable DrmInitData drmInitData) {
    return new Format(id, null, sampleMimeType, codecs, bitrate, maxInputSize, width, height,
        frameRate, rotationDegrees, pixelWidthHeightRatio, projectionData, stereoMode,
        colorInfo, NO_VALUE, NO_VALUE, NO_VALUE, NO_VALUE, NO_VALUE, 0, null, NO_VALUE,
        OFFSET_SAMPLE_RELATIVE, initializationData, drmInitData, null);
  }

  // Audio.

  public static Format createAudioContainerFormat(
      @Nullable String id,
      @Nullable String containerMimeType,
      @Nullable String sampleMimeType,
      @Nullable String codecs,
      int bitrate,
      int channelCount,
      int sampleRate,
      List<byte[]> initializationData,
      @C.SelectionFlags int selectionFlags,
      @Nullable String language) {
    return new Format(id, containerMimeType, sampleMimeType, codecs, bitrate, NO_VALUE, NO_VALUE,
        NO_VALUE, NO_VALUE, NO_VALUE, NO_VALUE, null, NO_VALUE, null, channelCount, sampleRate,
        NO_VALUE, NO_VALUE, NO_VALUE, selectionFlags, language, NO_VALUE, OFFSET_SAMPLE_RELATIVE,
        initializationData, null, null);
  }

  public static Format createAudioSampleFormat(
      @Nullable String id,
      @Nullable String sampleMimeType,
      @Nullable String codecs,
      int bitrate,
      int maxInputSize,
      int channelCount,
      int sampleRate,
      List<byte[]> initializationData,
      @Nullable DrmInitData drmInitData,
      @C.SelectionFlags int selectionFlags,
      @Nullable String language) {
    return createAudioSampleFormat(id, sampleMimeType, codecs, bitrate, maxInputSize, channelCount,
        sampleRate, NO_VALUE, initializationData, drmInitData, selectionFlags, language);
  }

  public static Format createAudioSampleFormat(
      @Nullable String id,
      @Nullable String sampleMimeType,
      @Nullable String codecs,
      int bitrate,
      int maxInputSize,
      int channelCount,
      int sampleRate,
      @C.PcmEncoding int pcmEncoding,
      List<byte[]> initializationData,
      @Nullable DrmInitData drmInitData,
      @C.SelectionFlags int selectionFlags,
      @Nullable String language) {
    return createAudioSampleFormat(id, sampleMimeType, codecs, bitrate, maxInputSize, channelCount,
        sampleRate, pcmEncoding, NO_VALUE, NO_VALUE, initializationData, drmInitData,
        selectionFlags, language, null);
  }

  public static Format createAudioSampleFormat(
      @Nullable String id,
      @Nullable String sampleMimeType,
      @Nullable String codecs,
      int bitrate,
      int maxInputSize,
      int channelCount,
      int sampleRate,
      @C.PcmEncoding int pcmEncoding,
      int encoderDelay,
      int encoderPadding,
      List<byte[]> initializationData,
      @Nullable DrmInitData drmInitData,
      @C.SelectionFlags int selectionFlags,
      @Nullable String language,
      @Nullable Metadata metadata) {
    return new Format(id, null, sampleMimeType, codecs, bitrate, maxInputSize, NO_VALUE, NO_VALUE,
        NO_VALUE, NO_VALUE, NO_VALUE, null, NO_VALUE, null, channelCount, sampleRate, pcmEncoding,
        encoderDelay, encoderPadding, selectionFlags, language, NO_VALUE, OFFSET_SAMPLE_RELATIVE,
        initializationData, drmInitData, metadata);
  }

  // Text.

  public static Format createTextContainerFormat(
      @Nullable String id,
      @Nullable String containerMimeType,
      @Nullable String sampleMimeType,
      @Nullable String codecs,
      int bitrate,
      @C.SelectionFlags int selectionFlags,
      @Nullable String language) {
    return createTextContainerFormat(id, containerMimeType, sampleMimeType, codecs, bitrate,
        selectionFlags, language, NO_VALUE);
  }

  public static Format createTextContainerFormat(
      @Nullable String id,
      @Nullable String containerMimeType,
      @Nullable String sampleMimeType,
      @Nullable String codecs,
      int bitrate,
      @C.SelectionFlags int selectionFlags,
      @Nullable String language,
      int accessibilityChannel) {
    return new Format(id, containerMimeType, sampleMimeType, codecs, bitrate, NO_VALUE, NO_VALUE,
        NO_VALUE, NO_VALUE, NO_VALUE, NO_VALUE, null, NO_VALUE, null, NO_VALUE, NO_VALUE,
        NO_VALUE, NO_VALUE, NO_VALUE, selectionFlags, language, accessibilityChannel,
        OFFSET_SAMPLE_RELATIVE, null, null, null);
  }

  public static Format createTextSampleFormat(
      @Nullable String id,
      String sampleMimeType,
      @C.SelectionFlags int selectionFlags,
      @Nullable String language) {
    return createTextSampleFormat(id, sampleMimeType, selectionFlags, language, null);
  }

  public static Format createTextSampleFormat(
      @Nullable String id,
      String sampleMimeType,
      @C.SelectionFlags int selectionFlags,
      @Nullable String language,
      @Nullable DrmInitData drmInitData) {
    return createTextSampleFormat(id, sampleMimeType, null, NO_VALUE, selectionFlags, language,
        NO_VALUE, drmInitData, OFFSET_SAMPLE_RELATIVE, Collections.<byte[]>emptyList());
  }

  public static Format createTextSampleFormat(
      @Nullable String id,
      @Nullable String sampleMimeType,
      @Nullable String codecs,
      int bitrate,
      @C.SelectionFlags int selectionFlags,
      @Nullable String language,
      int accessibilityChannel,
      @Nullable DrmInitData drmInitData) {
    return createTextSampleFormat(id, sampleMimeType, codecs, bitrate, selectionFlags, language,
        accessibilityChannel, drmInitData, OFFSET_SAMPLE_RELATIVE, Collections.<byte[]>emptyList());
  }

  public static Format createTextSampleFormat(
      @Nullable String id,
      @Nullable String sampleMimeType,
      @Nullable String codecs,
      int bitrate,
      @C.SelectionFlags int selectionFlags,
      @Nullable String language,
      @Nullable DrmInitData drmInitData,
      long subsampleOffsetUs) {
    return createTextSampleFormat(id, sampleMimeType, codecs, bitrate, selectionFlags, language,
        NO_VALUE, drmInitData, subsampleOffsetUs, Collections.<byte[]>emptyList());
  }

  public static Format createTextSampleFormat(
      @Nullable String id,
      @Nullable String sampleMimeType,
      @Nullable String codecs,
      int bitrate,
      @C.SelectionFlags int selectionFlags,
      @Nullable String language,
      int accessibilityChannel,
      @Nullable DrmInitData drmInitData,
      long subsampleOffsetUs,
      List<byte[]> initializationData) {
    return new Format(id, null, sampleMimeType, codecs, bitrate, NO_VALUE, NO_VALUE, NO_VALUE,
        NO_VALUE, NO_VALUE, NO_VALUE, null, NO_VALUE, null, NO_VALUE, NO_VALUE, NO_VALUE, NO_VALUE,
        NO_VALUE, selectionFlags, language, accessibilityChannel, subsampleOffsetUs,
        initializationData, drmInitData, null);
  }

  // Image.

  public static Format createImageSampleFormat(
      @Nullable String id,
      @Nullable String sampleMimeType,
      @Nullable String codecs,
      int bitrate,
      @C.SelectionFlags int selectionFlags,
      List<byte[]> initializationData,
      @Nullable String language,
      @Nullable DrmInitData drmInitData) {
    return new Format(
        id,
        null,
        sampleMimeType,
        codecs,
        bitrate,
        NO_VALUE,
        NO_VALUE,
        NO_VALUE,
        NO_VALUE,
        NO_VALUE,
        NO_VALUE,
        null,
        NO_VALUE,
        null,
        NO_VALUE,
        NO_VALUE,
        NO_VALUE,
        NO_VALUE,
        NO_VALUE,
        selectionFlags,
        language,
        NO_VALUE,
        OFFSET_SAMPLE_RELATIVE,
        initializationData,
        drmInitData,
        null);
  }

  // Generic.

  public static Format createContainerFormat(
      @Nullable String id,
      @Nullable String containerMimeType,
      @Nullable String sampleMimeType,
      @Nullable String codecs,
      int bitrate,
      @C.SelectionFlags int selectionFlags,
      @Nullable String language) {
    return new Format(id, containerMimeType, sampleMimeType, codecs, bitrate, NO_VALUE, NO_VALUE,
        NO_VALUE, NO_VALUE, NO_VALUE, NO_VALUE, null, NO_VALUE, null, NO_VALUE, NO_VALUE, NO_VALUE,
        NO_VALUE, NO_VALUE, selectionFlags, language, NO_VALUE, OFFSET_SAMPLE_RELATIVE, null, null,
        null);
  }

  public static Format createSampleFormat(
      @Nullable String id, @Nullable String sampleMimeType, long subsampleOffsetUs) {
    return new Format(id, null, sampleMimeType, null, NO_VALUE, NO_VALUE, NO_VALUE, NO_VALUE,
        NO_VALUE, NO_VALUE, NO_VALUE, null, NO_VALUE, null, NO_VALUE, NO_VALUE, NO_VALUE, NO_VALUE,
        NO_VALUE, 0, null, NO_VALUE, subsampleOffsetUs, null, null, null);
  }

  public static Format createSampleFormat(
      @Nullable String id,
      @Nullable String sampleMimeType,
      @Nullable String codecs,
      int bitrate,
      @Nullable DrmInitData drmInitData) {
    return new Format(id, null, sampleMimeType, codecs, bitrate, NO_VALUE, NO_VALUE, NO_VALUE,
        NO_VALUE, NO_VALUE, NO_VALUE, null, NO_VALUE, null, NO_VALUE, NO_VALUE, NO_VALUE, NO_VALUE,
        NO_VALUE, 0, null, NO_VALUE, OFFSET_SAMPLE_RELATIVE, null, drmInitData, null);
  }

  /* package */ Format(
      @Nullable String id,
      @Nullable String containerMimeType,
      @Nullable String sampleMimeType,
      @Nullable String codecs,
      int bitrate,
      int maxInputSize,
      int width,
      int height,
      float frameRate,
      int rotationDegrees,
      float pixelWidthHeightRatio,
      @Nullable byte[] projectionData,
      @C.StereoMode int stereoMode,
      @Nullable ColorInfo colorInfo,
      int channelCount,
      int sampleRate,
      @C.PcmEncoding int pcmEncoding,
      int encoderDelay,
      int encoderPadding,
      @C.SelectionFlags int selectionFlags,
      @Nullable String language,
      int accessibilityChannel,
      long subsampleOffsetUs,
      @Nullable List<byte[]> initializationData,
      @Nullable DrmInitData drmInitData,
      @Nullable Metadata metadata) {
    this.id = id;
    this.containerMimeType = containerMimeType;
    this.sampleMimeType = sampleMimeType;
    this.codecs = codecs;
    this.bitrate = bitrate;
    this.maxInputSize = maxInputSize;
    this.width = width;
    this.height = height;
    this.frameRate = frameRate;
    this.rotationDegrees = rotationDegrees == Format.NO_VALUE ? 0 : rotationDegrees;
    this.pixelWidthHeightRatio =
        pixelWidthHeightRatio == Format.NO_VALUE ? 1 : pixelWidthHeightRatio;
    this.projectionData = projectionData;
    this.stereoMode = stereoMode;
    this.colorInfo = colorInfo;
    this.channelCount = channelCount;
    this.sampleRate = sampleRate;
    this.pcmEncoding = pcmEncoding;
    this.encoderDelay = encoderDelay == Format.NO_VALUE ? 0 : encoderDelay;
    this.encoderPadding = encoderPadding == Format.NO_VALUE ? 0 : encoderPadding;
    this.selectionFlags = selectionFlags;
    this.language = language;
    this.accessibilityChannel = accessibilityChannel;
    this.subsampleOffsetUs = subsampleOffsetUs;
    this.initializationData = initializationData == null ? Collections.<byte[]>emptyList()
        : initializationData;
    this.drmInitData = drmInitData;
    this.metadata = metadata;
  }

  @SuppressWarnings("ResourceType")
  /* package */ Format(Parcel in) {
    id = in.readString();
    containerMimeType = in.readString();
    sampleMimeType = in.readString();
    codecs = in.readString();
    bitrate = in.readInt();
    maxInputSize = in.readInt();
    width = in.readInt();
    height = in.readInt();
    frameRate = in.readFloat();
    rotationDegrees = in.readInt();
    pixelWidthHeightRatio = in.readFloat();
    boolean hasProjectionData = Util.readBoolean(in);
    projectionData = hasProjectionData ? in.createByteArray() : null;
    stereoMode = in.readInt();
    colorInfo = in.readParcelable(ColorInfo.class.getClassLoader());
    channelCount = in.readInt();
    sampleRate = in.readInt();
    pcmEncoding = in.readInt();
    encoderDelay = in.readInt();
    encoderPadding = in.readInt();
    selectionFlags = in.readInt();
    language = in.readString();
    accessibilityChannel = in.readInt();
    subsampleOffsetUs = in.readLong();
    int initializationDataSize = in.readInt();
    initializationData = new ArrayList<>(initializationDataSize);
    for (int i = 0; i < initializationDataSize; i++) {
      initializationData.add(in.createByteArray());
    }
    drmInitData = in.readParcelable(DrmInitData.class.getClassLoader());
    metadata = in.readParcelable(Metadata.class.getClassLoader());
  }

  public Format copyWithMaxInputSize(int maxInputSize) {
    return new Format(id, containerMimeType, sampleMimeType, codecs, bitrate, maxInputSize, width,
        height, frameRate, rotationDegrees, pixelWidthHeightRatio, projectionData, stereoMode,
        colorInfo, channelCount, sampleRate, pcmEncoding, encoderDelay, encoderPadding,
        selectionFlags, language, accessibilityChannel, subsampleOffsetUs, initializationData,
        drmInitData, metadata);
  }

  public Format copyWithSubsampleOffsetUs(long subsampleOffsetUs) {
    return new Format(id, containerMimeType, sampleMimeType, codecs, bitrate, maxInputSize, width,
        height, frameRate, rotationDegrees, pixelWidthHeightRatio, projectionData, stereoMode,
        colorInfo, channelCount, sampleRate, pcmEncoding, encoderDelay, encoderPadding,
        selectionFlags, language, accessibilityChannel, subsampleOffsetUs, initializationData,
        drmInitData, metadata);
  }

  public Format copyWithContainerInfo(
      @Nullable String id,
      @Nullable String sampleMimeType,
      @Nullable String codecs,
      int bitrate,
      int width,
      int height,
      @C.SelectionFlags int selectionFlags,
      @Nullable String language) {
    return new Format(id, containerMimeType, sampleMimeType, codecs, bitrate, maxInputSize, width,
        height, frameRate, rotationDegrees, pixelWidthHeightRatio, projectionData, stereoMode,
        colorInfo, channelCount, sampleRate, pcmEncoding, encoderDelay, encoderPadding,
        selectionFlags, language, accessibilityChannel, subsampleOffsetUs, initializationData,
        drmInitData, metadata);
  }

  @SuppressWarnings("ReferenceEquality")
  public Format copyWithManifestFormatInfo(Format manifestFormat) {
    if (this == manifestFormat) {
      // No need to copy from ourselves.
      return this;
    }
    String id = manifestFormat.id;
    String codecs = this.codecs == null ? manifestFormat.codecs : this.codecs;
    int bitrate = this.bitrate == NO_VALUE ? manifestFormat.bitrate : this.bitrate;
    float frameRate = this.frameRate == NO_VALUE ? manifestFormat.frameRate : this.frameRate;
    @C.SelectionFlags int selectionFlags = this.selectionFlags |  manifestFormat.selectionFlags;
    String language = this.language == null ? manifestFormat.language : this.language;
    DrmInitData drmInitData =
        DrmInitData.createSessionCreationData(manifestFormat.drmInitData, this.drmInitData);
    return new Format(id, containerMimeType, sampleMimeType, codecs, bitrate, maxInputSize, width,
        height, frameRate, rotationDegrees, pixelWidthHeightRatio, projectionData, stereoMode,
        colorInfo, channelCount, sampleRate, pcmEncoding, encoderDelay, encoderPadding,
        selectionFlags, language, accessibilityChannel, subsampleOffsetUs, initializationData,
        drmInitData, metadata);
  }

  public Format copyWithGaplessInfo(int encoderDelay, int encoderPadding) {
    return new Format(id, containerMimeType, sampleMimeType, codecs, bitrate, maxInputSize, width,
        height, frameRate, rotationDegrees, pixelWidthHeightRatio, projectionData, stereoMode,
        colorInfo, channelCount, sampleRate, pcmEncoding, encoderDelay, encoderPadding,
        selectionFlags, language, accessibilityChannel, subsampleOffsetUs, initializationData,
        drmInitData, metadata);
  }

  public Format copyWithDrmInitData(@Nullable DrmInitData drmInitData) {
    return new Format(id, containerMimeType, sampleMimeType, codecs, bitrate, maxInputSize, width,
        height, frameRate, rotationDegrees, pixelWidthHeightRatio, projectionData, stereoMode,
        colorInfo, channelCount, sampleRate, pcmEncoding, encoderDelay, encoderPadding,
        selectionFlags, language, accessibilityChannel, subsampleOffsetUs, initializationData,
        drmInitData, metadata);
  }

  public Format copyWithMetadata(@Nullable Metadata metadata) {
    return new Format(id, containerMimeType, sampleMimeType, codecs, bitrate, maxInputSize, width,
        height, frameRate, rotationDegrees, pixelWidthHeightRatio, projectionData, stereoMode,
        colorInfo, channelCount, sampleRate, pcmEncoding, encoderDelay, encoderPadding,
        selectionFlags, language, accessibilityChannel, subsampleOffsetUs, initializationData,
        drmInitData, metadata);
  }

  public Format copyWithRotationDegrees(int rotationDegrees) {
    return new Format(id, containerMimeType, sampleMimeType, codecs, bitrate, maxInputSize, width,
        height, frameRate, rotationDegrees, pixelWidthHeightRatio, projectionData, stereoMode,
        colorInfo, channelCount, sampleRate, pcmEncoding, encoderDelay, encoderPadding,
        selectionFlags, language, accessibilityChannel, subsampleOffsetUs, initializationData,
        drmInitData, metadata);
  }

  /**
   * Returns the number of pixels if this is a video format whose {@link #width} and {@link #height}
   * are known, or {@link #NO_VALUE} otherwise
   */
  public int getPixelCount() {
    return width == NO_VALUE || height == NO_VALUE ? NO_VALUE : (width * height);
  }

  @Override
  public String toString() {
    return "Format(" + id + ", " + containerMimeType + ", " + sampleMimeType + ", " + bitrate + ", "
        + language + ", [" + width + ", " + height + ", " + frameRate + "]"
        + ", [" + channelCount + ", " + sampleRate + "])";
  }

  @Override
  public int hashCode() {
    if (hashCode == 0) {
      int result = 17;
      result = 31 * result + (id == null ? 0 : id.hashCode());
      result = 31 * result + (containerMimeType == null ? 0 : containerMimeType.hashCode());
      result = 31 * result + (sampleMimeType == null ? 0 : sampleMimeType.hashCode());
      result = 31 * result + (codecs == null ? 0 : codecs.hashCode());
      result = 31 * result + bitrate;
      result = 31 * result + width;
      result = 31 * result + height;
      result = 31 * result + channelCount;
      result = 31 * result + sampleRate;
      result = 31 * result + (language == null ? 0 : language.hashCode());
      result = 31 * result + accessibilityChannel;
      result = 31 * result + (drmInitData == null ? 0 : drmInitData.hashCode());
      result = 31 * result + (metadata == null ? 0 : metadata.hashCode());
      hashCode = result;
    }
    return hashCode;
  }

  @Override
  public boolean equals(@Nullable Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null || getClass() != obj.getClass()) {
      return false;
    }
    Format other = (Format) obj;
    return bitrate == other.bitrate
        && maxInputSize == other.maxInputSize
        && width == other.width
        && height == other.height
        && frameRate == other.frameRate
        && rotationDegrees == other.rotationDegrees
        && pixelWidthHeightRatio == other.pixelWidthHeightRatio
        && stereoMode == other.stereoMode
        && channelCount == other.channelCount
        && sampleRate == other.sampleRate
        && pcmEncoding == other.pcmEncoding
        && encoderDelay == other.encoderDelay
        && encoderPadding == other.encoderPadding
        && subsampleOffsetUs == other.subsampleOffsetUs
        && selectionFlags == other.selectionFlags
        && Util.areEqual(id, other.id)
        && Util.areEqual(language, other.language)
        && accessibilityChannel == other.accessibilityChannel
        && Util.areEqual(containerMimeType, other.containerMimeType)
        && Util.areEqual(sampleMimeType, other.sampleMimeType)
        && Util.areEqual(codecs, other.codecs)
        && Util.areEqual(drmInitData, other.drmInitData)
        && Util.areEqual(metadata, other.metadata)
        && Util.areEqual(colorInfo, other.colorInfo)
        && Arrays.equals(projectionData, other.projectionData)
        && initializationDataEquals(other);
  }

  /**
   * Returns whether the {@link #initializationData}s belonging to this format and {@code other} are
   * equal.
   *
   * @param other The other format whose {@link #initializationData} is being compared.
   * @return Whether the {@link #initializationData}s belonging to this format and {@code other} are
   *     equal.
   */
  public boolean initializationDataEquals(Format other) {
    if (initializationData.size() != other.initializationData.size()) {
      return false;
    }
    for (int i = 0; i < initializationData.size(); i++) {
      if (!Arrays.equals(initializationData.get(i), other.initializationData.get(i))) {
        return false;
      }
    }
    return true;
  }

  // Utility methods

  /**
   * Returns a prettier {@link String} than {@link #toString()}, intended for logging.
   */
  public static String toLogString(Format format) {
    if (format == null) {
      return "null";
    }
    StringBuilder builder = new StringBuilder();
    builder.append("id=").append(format.id).append(", mimeType=").append(format.sampleMimeType);
    if (format.bitrate != Format.NO_VALUE) {
      builder.append(", bitrate=").append(format.bitrate);
    }
    if (format.width != Format.NO_VALUE && format.height != Format.NO_VALUE) {
      builder.append(", res=").append(format.width).append("x").append(format.height);
    }
    if (format.frameRate != Format.NO_VALUE) {
      builder.append(", fps=").append(format.frameRate);
    }
    if (format.channelCount != Format.NO_VALUE) {
      builder.append(", channels=").append(format.channelCount);
    }
    if (format.sampleRate != Format.NO_VALUE) {
      builder.append(", sample_rate=").append(format.sampleRate);
    }
    if (format.language != null) {
      builder.append(", language=").append(format.language);
    }
    return builder.toString();
  }

  // Parcelable implementation.

  @Override
  public int describeContents() {
    return 0;
  }

  @Override
  public void writeToParcel(Parcel dest, int flags) {
    dest.writeString(id);
    dest.writeString(containerMimeType);
    dest.writeString(sampleMimeType);
    dest.writeString(codecs);
    dest.writeInt(bitrate);
    dest.writeInt(maxInputSize);
    dest.writeInt(width);
    dest.writeInt(height);
    dest.writeFloat(frameRate);
    dest.writeInt(rotationDegrees);
    dest.writeFloat(pixelWidthHeightRatio);
    Util.writeBoolean(dest, projectionData != null);
    if (projectionData != null) {
      dest.writeByteArray(projectionData);
    }
    dest.writeInt(stereoMode);
    dest.writeParcelable(colorInfo, flags);
    dest.writeInt(channelCount);
    dest.writeInt(sampleRate);
    dest.writeInt(pcmEncoding);
    dest.writeInt(encoderDelay);
    dest.writeInt(encoderPadding);
    dest.writeInt(selectionFlags);
    dest.writeString(language);
    dest.writeInt(accessibilityChannel);
    dest.writeLong(subsampleOffsetUs);
    int initializationDataSize = initializationData.size();
    dest.writeInt(initializationDataSize);
    for (int i = 0; i < initializationDataSize; i++) {
      dest.writeByteArray(initializationData.get(i));
    }
    dest.writeParcelable(drmInitData, 0);
    dest.writeParcelable(metadata, 0);
  }

  public static final Creator<Format> CREATOR = new Creator<Format>() {

    @Override
    public Format createFromParcel(Parcel in) {
      return new Format(in);
    }

    @Override
    public Format[] newArray(int size) {
      return new Format[size];
    }

  };
}
