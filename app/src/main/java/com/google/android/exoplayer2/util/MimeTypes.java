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
package com.google.android.exoplayer2.util;

import android.text.TextUtils;

import androidx.annotation.Nullable;

import com.google.android.exoplayer2.C;

/**
 * Defines common MIME types and helper methods.
 */
public final class MimeTypes {

  public static final String BASE_TYPE_VIDEO = "video";
  public static final String BASE_TYPE_AUDIO = "audio";
  public static final String BASE_TYPE_TEXT = "text";
  public static final String BASE_TYPE_APPLICATION = "application";

  public static final String VIDEO_MP4 = BASE_TYPE_VIDEO + "/mp4";
  public static final String VIDEO_WEBM = BASE_TYPE_VIDEO + "/webm";
  public static final String VIDEO_H263 = BASE_TYPE_VIDEO + "/3gpp";
  public static final String VIDEO_H264 = BASE_TYPE_VIDEO + "/avc";
  public static final String VIDEO_H265 = BASE_TYPE_VIDEO + "/hevc";
  public static final String VIDEO_VP8 = BASE_TYPE_VIDEO + "/x-vnd.on2.vp8";
  public static final String VIDEO_VP9 = BASE_TYPE_VIDEO + "/x-vnd.on2.vp9";
  public static final String VIDEO_MP4V = BASE_TYPE_VIDEO + "/mp4v-es";
  public static final String VIDEO_MPEG = BASE_TYPE_VIDEO + "/mpeg";
  public static final String VIDEO_MPEG2 = BASE_TYPE_VIDEO + "/mpeg2";
  public static final String VIDEO_VC1 = BASE_TYPE_VIDEO + "/wvc1";
  public static final String VIDEO_UNKNOWN = BASE_TYPE_VIDEO + "/x-unknown";

  public static final String AUDIO_MP4 = BASE_TYPE_AUDIO + "/mp4";
  public static final String AUDIO_AAC = BASE_TYPE_AUDIO + "/mp4a-latm";
  public static final String AUDIO_WEBM = BASE_TYPE_AUDIO + "/webm";
  public static final String AUDIO_MPEG = BASE_TYPE_AUDIO + "/mpeg";
  public static final String AUDIO_MPEG_L1 = BASE_TYPE_AUDIO + "/mpeg-L1";
  public static final String AUDIO_MPEG_L2 = BASE_TYPE_AUDIO + "/mpeg-L2";
  public static final String AUDIO_RAW = BASE_TYPE_AUDIO + "/raw";
  public static final String AUDIO_ALAW = BASE_TYPE_AUDIO + "/g711-alaw";
  public static final String AUDIO_MLAW = BASE_TYPE_AUDIO + "/g711-mlaw";
  public static final String AUDIO_AC3 = BASE_TYPE_AUDIO + "/ac3";
  public static final String AUDIO_E_AC3 = BASE_TYPE_AUDIO + "/eac3";
  public static final String AUDIO_E_AC3_JOC = BASE_TYPE_AUDIO + "/eac3-joc";
  public static final String AUDIO_TRUEHD = BASE_TYPE_AUDIO + "/true-hd";
  public static final String AUDIO_DTS = BASE_TYPE_AUDIO + "/vnd.dts";
  public static final String AUDIO_DTS_HD = BASE_TYPE_AUDIO + "/vnd.dts.hd";
  public static final String AUDIO_DTS_EXPRESS = BASE_TYPE_AUDIO + "/vnd.dts.hd;profile=lbr";
  public static final String AUDIO_VORBIS = BASE_TYPE_AUDIO + "/vorbis";
  public static final String AUDIO_OPUS = BASE_TYPE_AUDIO + "/opus";
  public static final String AUDIO_AMR_NB = BASE_TYPE_AUDIO + "/3gpp";
  public static final String AUDIO_AMR_WB = BASE_TYPE_AUDIO + "/amr-wb";
  public static final String AUDIO_FLAC = BASE_TYPE_AUDIO + "/flac";
  public static final String AUDIO_ALAC = BASE_TYPE_AUDIO + "/alac";
  public static final String AUDIO_MSGSM = BASE_TYPE_AUDIO + "/gsm";
  public static final String AUDIO_UNKNOWN = BASE_TYPE_AUDIO + "/x-unknown";

  public static final String TEXT_VTT = BASE_TYPE_TEXT + "/vtt";
  public static final String TEXT_SSA = BASE_TYPE_TEXT + "/x-ssa";

  public static final String APPLICATION_MP4 = BASE_TYPE_APPLICATION + "/mp4";
  public static final String APPLICATION_WEBM = BASE_TYPE_APPLICATION + "/webm";
  public static final String APPLICATION_MPD = BASE_TYPE_APPLICATION + "/dash+xml";
  public static final String APPLICATION_M3U8 = BASE_TYPE_APPLICATION + "/x-mpegURL";
  public static final String APPLICATION_SS = BASE_TYPE_APPLICATION + "/vnd.ms-sstr+xml";
  public static final String APPLICATION_ID3 = BASE_TYPE_APPLICATION + "/id3";
  public static final String APPLICATION_CEA608 = BASE_TYPE_APPLICATION + "/cea-608";
  public static final String APPLICATION_CEA708 = BASE_TYPE_APPLICATION + "/cea-708";
  public static final String APPLICATION_SUBRIP = BASE_TYPE_APPLICATION + "/x-subrip";
  public static final String APPLICATION_TTML = BASE_TYPE_APPLICATION + "/ttml+xml";
  public static final String APPLICATION_TX3G = BASE_TYPE_APPLICATION + "/x-quicktime-tx3g";
  public static final String APPLICATION_MP4VTT = BASE_TYPE_APPLICATION + "/x-mp4-vtt";
  public static final String APPLICATION_MP4CEA608 = BASE_TYPE_APPLICATION + "/x-mp4-cea-608";
  public static final String APPLICATION_RAWCC = BASE_TYPE_APPLICATION + "/x-rawcc";
  public static final String APPLICATION_VOBSUB = BASE_TYPE_APPLICATION + "/vobsub";
  public static final String APPLICATION_PGS = BASE_TYPE_APPLICATION + "/pgs";
  public static final String APPLICATION_SCTE35 = BASE_TYPE_APPLICATION + "/x-scte35";
  public static final String APPLICATION_CAMERA_MOTION = BASE_TYPE_APPLICATION + "/x-camera-motion";
  public static final String APPLICATION_EMSG = BASE_TYPE_APPLICATION + "/x-emsg";
  public static final String APPLICATION_DVBSUBS = BASE_TYPE_APPLICATION + "/dvbsubs";
  public static final String APPLICATION_EXIF = BASE_TYPE_APPLICATION + "/x-exif";

  private MimeTypes() {}

  /**
   * Whether the top-level type of {@code mimeType} is audio.
   *
   * @param mimeType The mimeType to test.
   * @return Whether the top level type is audio.
   */
  public static boolean isAudio(String mimeType) {
    return BASE_TYPE_AUDIO.equals(getTopLevelType(mimeType));
  }

  /**
   * Whether the top-level type of {@code mimeType} is video.
   *
   * @param mimeType The mimeType to test.
   * @return Whether the top level type is video.
   */
  public static boolean isVideo(String mimeType) {
    return BASE_TYPE_VIDEO.equals(getTopLevelType(mimeType));
  }

  /**
   * Whether the top-level type of {@code mimeType} is text.
   *
   * @param mimeType The mimeType to test.
   * @return Whether the top level type is text.
   */
  public static boolean isText(String mimeType) {
    return BASE_TYPE_TEXT.equals(getTopLevelType(mimeType));
  }

  /**
   * Whether the top-level type of {@code mimeType} is application.
   *
   * @param mimeType The mimeType to test.
   * @return Whether the top level type is application.
   */
  public static boolean isApplication(String mimeType) {
    return BASE_TYPE_APPLICATION.equals(getTopLevelType(mimeType));
  }

  /**
   * Derives a video sample mimeType from a codecs attribute.
   *
   * @param codecs The codecs attribute.
   * @return The derived video mimeType, or null if it could not be derived.
   */
  public static @Nullable String getVideoMediaMimeType(@Nullable String codecs) {
    if (codecs == null) {
      return null;
    }
    String[] codecList = codecs.split(",");
    for (String codec : codecList) {
      String mimeType = getMediaMimeType(codec);
      if (mimeType != null && isVideo(mimeType)) {
        return mimeType;
      }
    }
    return null;
  }

  /**
   * Derives a audio sample mimeType from a codecs attribute.
   *
   * @param codecs The codecs attribute.
   * @return The derived audio mimeType, or null if it could not be derived.
   */
  public static @Nullable String getAudioMediaMimeType(@Nullable String codecs) {
    if (codecs == null) {
      return null;
    }
    String[] codecList = codecs.split(",");
    for (String codec : codecList) {
      String mimeType = getMediaMimeType(codec);
      if (mimeType != null && isAudio(mimeType)) {
        return mimeType;
      }
    }
    return null;
  }

  /**
   * Derives a mimeType from a codec identifier, as defined in RFC 6381.
   *
   * @param codec The codec identifier to derive.
   * @return The mimeType, or null if it could not be derived.
   */
  public static @Nullable String getMediaMimeType(@Nullable String codec) {
    if (codec == null) {
      return null;
    }
    codec = codec.trim();
    if (codec.startsWith("avc1") || codec.startsWith("avc3")) {
      return MimeTypes.VIDEO_H264;
    } else if (codec.startsWith("hev1") || codec.startsWith("hvc1")) {
      return MimeTypes.VIDEO_H265;
    } else if (codec.startsWith("vp9") || codec.startsWith("vp09")) {
      return MimeTypes.VIDEO_VP9;
    } else if (codec.startsWith("vp8") || codec.startsWith("vp08")) {
      return MimeTypes.VIDEO_VP8;
    } else if (codec.startsWith("mp4a")) {
      String mimeType = null;
      if (codec.startsWith("mp4a.")) {
        String objectTypeString = codec.substring(5); // remove the 'mp4a.' prefix
        if (objectTypeString.length() >= 2) {
          try {
            String objectTypeHexString = Util.toUpperInvariant(objectTypeString.substring(0, 2));
            int objectTypeInt = Integer.parseInt(objectTypeHexString, 16);
            mimeType = getMimeTypeFromMp4ObjectType(objectTypeInt);
          } catch (NumberFormatException ignored) {
            // ignored
          }
        }
      }
      return mimeType == null ? MimeTypes.AUDIO_AAC : mimeType;
    } else if (codec.startsWith("ac-3") || codec.startsWith("dac3")) {
      return MimeTypes.AUDIO_AC3;
    } else if (codec.startsWith("ec-3") || codec.startsWith("dec3")) {
      return MimeTypes.AUDIO_E_AC3;
    } else if (codec.startsWith("ec+3")) {
      return MimeTypes.AUDIO_E_AC3_JOC;
    } else if (codec.startsWith("dtsc") || codec.startsWith("dtse")) {
      return MimeTypes.AUDIO_DTS;
    } else if (codec.startsWith("dtsh") || codec.startsWith("dtsl")) {
      return MimeTypes.AUDIO_DTS_HD;
    } else if (codec.startsWith("opus")) {
      return MimeTypes.AUDIO_OPUS;
    } else if (codec.startsWith("vorbis")) {
      return MimeTypes.AUDIO_VORBIS;
    }
    return null;
  }

  /**
   * Derives a mimeType from MP4 object type identifier, as defined in RFC 6381 and
   * http://www.mp4ra.org/object.html.
   *
   * @param objectType The objectType identifier to derive.
   * @return The mimeType, or null if it could not be derived.
   */
  @Nullable
  public static String getMimeTypeFromMp4ObjectType(int objectType) {
    switch (objectType) {
      case 0x60:
      case 0x61:
        return MimeTypes.VIDEO_MPEG2;
      case 0x20:
        return MimeTypes.VIDEO_MP4V;
      case 0x21:
        return MimeTypes.VIDEO_H264;
      case 0x23:
        return MimeTypes.VIDEO_H265;
      case 0x69:
      case 0x6B:
        return MimeTypes.AUDIO_MPEG;
      case 0x40:
      case 0x66:
      case 0x67:
      case 0x68:
        return MimeTypes.AUDIO_AAC;
      case 0xA5:
        return MimeTypes.AUDIO_AC3;
      case 0xA6:
        return MimeTypes.AUDIO_E_AC3;
      case 0xA9:
      case 0xAC:
        return MimeTypes.AUDIO_DTS;
      case 0xAA:
      case 0xAB:
        return MimeTypes.AUDIO_DTS_HD;
      case 0xAD:
        return MimeTypes.AUDIO_OPUS;
      default:
        return null;
    }
  }

  /**
   * Returns the {@link C}{@code .TRACK_TYPE_*} constant that corresponds to a specified MIME type.
   * {@link C#TRACK_TYPE_UNKNOWN} if the MIME type is not known or the mapping cannot be
   * established.
   *
   * @param mimeType The MIME type.
   * @return The {@link C}{@code .TRACK_TYPE_*} constant that corresponds to a specified MIME type.
   */
  public static int getTrackType(String mimeType) {
    if (TextUtils.isEmpty(mimeType)) {
      return C.TRACK_TYPE_UNKNOWN;
    } else if (isAudio(mimeType)) {
      return C.TRACK_TYPE_AUDIO;
    } else if (isVideo(mimeType)) {
      return C.TRACK_TYPE_VIDEO;
    } else if (isText(mimeType) || APPLICATION_CEA608.equals(mimeType)
        || APPLICATION_CEA708.equals(mimeType) || APPLICATION_MP4CEA608.equals(mimeType)
        || APPLICATION_SUBRIP.equals(mimeType) || APPLICATION_TTML.equals(mimeType)
        || APPLICATION_TX3G.equals(mimeType) || APPLICATION_MP4VTT.equals(mimeType)
        || APPLICATION_RAWCC.equals(mimeType) || APPLICATION_VOBSUB.equals(mimeType)
        || APPLICATION_PGS.equals(mimeType) || APPLICATION_DVBSUBS.equals(mimeType)) {
      return C.TRACK_TYPE_TEXT;
    } else if (APPLICATION_ID3.equals(mimeType)
        || APPLICATION_EMSG.equals(mimeType)
        || APPLICATION_SCTE35.equals(mimeType)
        || APPLICATION_CAMERA_MOTION.equals(mimeType)) {
      return C.TRACK_TYPE_METADATA;
    } else {
      return C.TRACK_TYPE_UNKNOWN;
    }
  }

  /**
   * Returns the {@link C}{@code .ENCODING_*} constant that corresponds to specified MIME type, if
   * it is an encoded (non-PCM) audio format, or {@link C#ENCODING_INVALID} otherwise.
   *
   * @param mimeType The MIME type.
   * @return The {@link C}{@code .ENCODING_*} constant that corresponds to a specified MIME type, or
   *     {@link C#ENCODING_INVALID}.
   */
  public static @C.Encoding int getEncoding(String mimeType) {
    switch (mimeType) {
      case MimeTypes.AUDIO_AC3:
        return C.ENCODING_AC3;
      case MimeTypes.AUDIO_E_AC3:
      case MimeTypes.AUDIO_E_AC3_JOC:
        return C.ENCODING_E_AC3;
      case MimeTypes.AUDIO_DTS:
        return C.ENCODING_DTS;
      case MimeTypes.AUDIO_DTS_HD:
        return C.ENCODING_DTS_HD;
      case MimeTypes.AUDIO_TRUEHD:
        return C.ENCODING_DOLBY_TRUEHD;
      default:
        return C.ENCODING_INVALID;
    }
  }

  /**
   * Equivalent to {@code getTrackType(getMediaMimeType(codec))}.
   *
   * @param codec The codec.
   * @return The {@link C}{@code .TRACK_TYPE_*} constant that corresponds to a specified codec.
   */
  public static int getTrackTypeOfCodec(String codec) {
    return getTrackType(getMediaMimeType(codec));
  }

  /**
   * Returns the top-level type of {@code mimeType}.
   *
   * @param mimeType The mimeType whose top-level type is required.
   * @return The top-level type, or null if the mimeType is null.
   */
  private static @Nullable String getTopLevelType(@Nullable String mimeType) {
    if (mimeType == null) {
      return null;
    }
    int indexOfSlash = mimeType.indexOf('/');
    if (indexOfSlash == -1) {
      throw new IllegalArgumentException("Invalid mime type: " + mimeType);
    }
    return mimeType.substring(0, indexOfSlash);
  }

}
