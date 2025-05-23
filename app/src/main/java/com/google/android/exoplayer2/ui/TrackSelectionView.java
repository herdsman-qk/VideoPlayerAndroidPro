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
package com.google.android.exoplayer2.ui;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.util.Pair;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.CheckedTextView;
import android.widget.LinearLayout;

import androidx.annotation.AttrRes;
import androidx.annotation.Nullable;

import com.google.android.exoplayer2.RendererCapabilities;
import com.google.android.exoplayer2.source.TrackGroup;
import com.google.android.exoplayer2.source.TrackGroupArray;
import com.dev.videoandpdf.R;
import com.google.android.exoplayer2.trackselection.DefaultTrackSelector;
import com.google.android.exoplayer2.trackselection.DefaultTrackSelector.SelectionOverride;
import com.google.android.exoplayer2.trackselection.MappingTrackSelector;
import com.google.android.exoplayer2.util.Assertions;

import java.util.Arrays;

/** A view for making track selections. */
public class TrackSelectionView extends LinearLayout {

  private final int selectableItemBackgroundResourceId;
  private final LayoutInflater inflater;
  private final CheckedTextView disableView;
  private final CheckedTextView defaultView;
  private final ComponentListener componentListener;

  private boolean allowAdaptiveSelections;

  private TrackNameProvider trackNameProvider;
  private CheckedTextView[][] trackViews;

  private DefaultTrackSelector trackSelector;
  private int rendererIndex;
  private TrackGroupArray trackGroups;
  private boolean isDisabled;
  private @Nullable SelectionOverride override;

  /**
   * Gets a pair consisting of a dialog and the {@link TrackSelectionView} that will be shown by it.
   *
   * @param activity The parent activity.
   * @param title The dialog's title.
   * @param trackSelector The track selector.
   * @param rendererIndex The index of the renderer.
   * @return The dialog and the {@link TrackSelectionView} that will be shown by it.
   */
  public static Pair<AlertDialog, TrackSelectionView> getDialog(
      Activity activity,
      CharSequence title,
      DefaultTrackSelector trackSelector,
      int rendererIndex) {
    AlertDialog.Builder builder = new AlertDialog.Builder(activity);

    // Inflate with the builder's context to ensure the correct style is used.
    LayoutInflater dialogInflater = LayoutInflater.from(builder.getContext());
    View dialogView = dialogInflater.inflate(R.layout.exo_track_selection_dialog, null);

    final TrackSelectionView selectionView = dialogView.findViewById(R.id.exo_track_selection_view);
    selectionView.init(trackSelector, rendererIndex);
    Dialog.OnClickListener okClickListener =
        new Dialog.OnClickListener() {
          @Override
          public void onClick(DialogInterface dialog, int which) {
            selectionView.applySelection();
          }
        };

    AlertDialog dialog =
        builder
            .setTitle(title)
            .setView(dialogView)
            .setPositiveButton(android.R.string.ok, okClickListener)
            .setNegativeButton(android.R.string.cancel, null)
            .create();
    return Pair.create(dialog, selectionView);
  }

  public TrackSelectionView(Context context) {
    this(context, null);
  }

  public TrackSelectionView(Context context, @Nullable AttributeSet attrs) {
    this(context, attrs, 0);
  }

  @SuppressWarnings("nullness")
  public TrackSelectionView(
      Context context, @Nullable AttributeSet attrs, @AttrRes int defStyleAttr) {
    super(context, attrs, defStyleAttr);
    TypedArray attributeArray =
        context
            .getTheme()
            .obtainStyledAttributes(new int[] {android.R.attr.selectableItemBackground});
    selectableItemBackgroundResourceId = attributeArray.getResourceId(0, 0);
    attributeArray.recycle();

    inflater = LayoutInflater.from(context);
    componentListener = new ComponentListener();
    trackNameProvider = new DefaultTrackNameProvider(getResources());

    // View for disabling the renderer.
    disableView =
        (CheckedTextView)
            inflater.inflate(android.R.layout.simple_list_item_single_choice, this, false);
    disableView.setBackgroundResource(selectableItemBackgroundResourceId);
    disableView.setText(R.string.exo_track_selection_none);
    disableView.setEnabled(false);
    disableView.setFocusable(true);
    disableView.setOnClickListener(componentListener);
    disableView.setVisibility(View.GONE);
    addView(disableView);
    // Divider view.
    addView(inflater.inflate(R.layout.exo_list_divider, this, false));
    // View for clearing the override to allow the selector to use its default selection logic.
    defaultView =
        (CheckedTextView)
            inflater.inflate(android.R.layout.simple_list_item_single_choice, this, false);
    defaultView.setBackgroundResource(selectableItemBackgroundResourceId);
    defaultView.setText(R.string.exo_track_selection_auto);
    defaultView.setEnabled(false);
    defaultView.setFocusable(true);
    defaultView.setOnClickListener(componentListener);
    addView(defaultView);
  }

  /**
   * Sets whether adaptive selections (consisting of more than one track) can be made using this
   * selection view.
   *
   * <p>For the view to enable adaptive selection it is necessary both for this feature to be
   * enabled, and for the target renderer to support adaptation between the available tracks.
   *
   * @param allowAdaptiveSelections Whether adaptive selection is enabled.
   */
  public void setAllowAdaptiveSelections(boolean allowAdaptiveSelections) {
    if (this.allowAdaptiveSelections != allowAdaptiveSelections) {
      this.allowAdaptiveSelections = allowAdaptiveSelections;
      updateViews();
    }
  }

  /**
   * Sets whether an option is available for disabling the renderer.
   *
   * @param showDisableOption Whether the disable option is shown.
   */
  public void setShowDisableOption(boolean showDisableOption) {
    disableView.setVisibility(showDisableOption ? View.VISIBLE : View.GONE);
  }

  /**
   * Sets the {@link TrackNameProvider} used to generate the user visible name of each track and
   * updates the view with track names queried from the specified provider.
   *
   * @param trackNameProvider The {@link TrackNameProvider} to use.
   */
  public void setTrackNameProvider(TrackNameProvider trackNameProvider) {
    this.trackNameProvider = Assertions.checkNotNull(trackNameProvider);
    updateViews();
  }

  /**
   * Initialize the view to select tracks for a specified renderer using a {@link
   * DefaultTrackSelector}.
   *
   * @param trackSelector The {@link DefaultTrackSelector}.
   * @param rendererIndex The index of the renderer.
   */
  public void init(DefaultTrackSelector trackSelector, int rendererIndex) {
    this.trackSelector = trackSelector;
    this.rendererIndex = rendererIndex;
    updateViews();
  }

  // Private methods.

  private void updateViews() {
    // Remove previous per-track views.
    for (int i = getChildCount() - 1; i >= 3; i--) {
      removeViewAt(i);
    }

    if (trackSelector == null) {
      // The view is not initialized.
      disableView.setEnabled(false);
      defaultView.setEnabled(false);
      return;
    }
    disableView.setEnabled(true);
    defaultView.setEnabled(true);

    MappingTrackSelector.MappedTrackInfo trackInfo = trackSelector.getCurrentMappedTrackInfo();
    trackGroups = trackInfo.getTrackGroups(rendererIndex);

    DefaultTrackSelector.Parameters parameters = trackSelector.getParameters();
    isDisabled = parameters.getRendererDisabled(rendererIndex);
    override = parameters.getSelectionOverride(rendererIndex, trackGroups);

    // Add per-track views.
    trackViews = new CheckedTextView[trackGroups.length][];
    for (int groupIndex = 0; groupIndex < trackGroups.length; groupIndex++) {
      TrackGroup group = trackGroups.get(groupIndex);
      boolean enableAdaptiveSelections =
          allowAdaptiveSelections
              && trackGroups.get(groupIndex).length > 1
              && trackInfo.getAdaptiveSupport(rendererIndex, groupIndex, false)
                  != RendererCapabilities.ADAPTIVE_NOT_SUPPORTED;
      trackViews[groupIndex] = new CheckedTextView[group.length];
      for (int trackIndex = 0; trackIndex < group.length; trackIndex++) {
        if (trackIndex == 0) {
          addView(inflater.inflate(R.layout.exo_list_divider, this, false));
        }
        int trackViewLayoutId =
            enableAdaptiveSelections
                ? android.R.layout.simple_list_item_multiple_choice
                : android.R.layout.simple_list_item_single_choice;
        CheckedTextView trackView =
            (CheckedTextView) inflater.inflate(trackViewLayoutId, this, false);
        trackView.setBackgroundResource(selectableItemBackgroundResourceId);
        trackView.setText(trackNameProvider.getTrackName(group.getFormat(trackIndex)));
        if (trackInfo.getTrackSupport(rendererIndex, groupIndex, trackIndex)
            == RendererCapabilities.FORMAT_HANDLED) {
          trackView.setFocusable(true);
          trackView.setTag(Pair.create(groupIndex, trackIndex));
          trackView.setOnClickListener(componentListener);
        } else {
          trackView.setFocusable(false);
          trackView.setEnabled(false);
        }
        trackViews[groupIndex][trackIndex] = trackView;
        addView(trackView);
      }
    }

    updateViewStates();
  }

  private void updateViewStates() {
    disableView.setChecked(isDisabled);
    defaultView.setChecked(!isDisabled && override == null);
    for (int i = 0; i < trackViews.length; i++) {
      for (int j = 0; j < trackViews[i].length; j++) {
        trackViews[i][j].setChecked(
            override != null && override.groupIndex == i && override.containsTrack(j));
      }
    }
  }

  private void applySelection() {
    DefaultTrackSelector.ParametersBuilder parametersBuilder = trackSelector.buildUponParameters();
    parametersBuilder.setRendererDisabled(rendererIndex, isDisabled);
    if (override != null) {
      parametersBuilder.setSelectionOverride(rendererIndex, trackGroups, override);
    } else {
      parametersBuilder.clearSelectionOverrides(rendererIndex);
    }
    trackSelector.setParameters(parametersBuilder);
  }

  private void onClick(View view) {
    if (view == disableView) {
      onDisableViewClicked();
    } else if (view == defaultView) {
      onDefaultViewClicked();
    } else {
      onTrackViewClicked(view);
    }
    updateViewStates();
  }

  private void onDisableViewClicked() {
    isDisabled = true;
    override = null;
  }

  private void onDefaultViewClicked() {
    isDisabled = false;
    override = null;
  }

  private void onTrackViewClicked(View view) {
    isDisabled = false;
    @SuppressWarnings("unchecked")
    Pair<Integer, Integer> tag = (Pair<Integer, Integer>) view.getTag();
    int groupIndex = tag.first;
    int trackIndex = tag.second;
    if (override == null || override.groupIndex != groupIndex || !allowAdaptiveSelections) {
      // A new override is being started.
      override = new SelectionOverride(groupIndex, trackIndex);
    } else {
      // An existing override is being modified.
      int overrideLength = override.length;
      int[] overrideTracks = override.tracks;
      if (((CheckedTextView) view).isChecked()) {
        // Remove the track from the override.
        if (overrideLength == 1) {
          // The last track is being removed, so the override becomes empty.
          override = null;
          isDisabled = true;
        } else {
          int[] tracks = getTracksRemoving(overrideTracks, trackIndex);
          override = new SelectionOverride(groupIndex, tracks);
        }
      } else {
        int[] tracks = getTracksAdding(overrideTracks, trackIndex);
        override = new SelectionOverride(groupIndex, tracks);
      }
    }
  }

  private static int[] getTracksAdding(int[] tracks, int addedTrack) {
    tracks = Arrays.copyOf(tracks, tracks.length + 1);
    tracks[tracks.length - 1] = addedTrack;
    return tracks;
  }

  private static int[] getTracksRemoving(int[] tracks, int removedTrack) {
    int[] newTracks = new int[tracks.length - 1];
    int trackCount = 0;
    for (int track : tracks) {
      if (track != removedTrack) {
        newTracks[trackCount++] = track;
      }
    }
    return newTracks;
  }

  // Internal classes.

  private class ComponentListener implements OnClickListener {

    @Override
    public void onClick(View view) {
      TrackSelectionView.this.onClick(view);
    }
  }
}
