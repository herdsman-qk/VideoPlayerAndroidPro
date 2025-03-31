package com.dev.kee.video;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.media.AudioManager;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.util.Log;
import android.util.Pair;
import android.view.GestureDetector;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.Window;
import android.view.WindowManager;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.AppCompatImageView;

import com.dev.videoandpdf.R;
import com.google.android.exoplayer2.C;
import com.google.android.exoplayer2.DefaultRenderersFactory;
import com.google.android.exoplayer2.ExoPlaybackException;
import com.google.android.exoplayer2.ExoPlayerFactory;
import com.google.android.exoplayer2.PlaybackPreparer;
import com.google.android.exoplayer2.Player;
import com.google.android.exoplayer2.SimpleExoPlayer;
import com.google.android.exoplayer2.drm.DefaultDrmSessionManager;
import com.google.android.exoplayer2.drm.FrameworkMediaCrypto;
import com.google.android.exoplayer2.mediacodec.MediaCodecRenderer.DecoderInitializationException;
import com.google.android.exoplayer2.source.BehindLiveWindowException;
import com.google.android.exoplayer2.source.ConcatenatingMediaSource;
import com.google.android.exoplayer2.source.ExtractorMediaSource;
import com.google.android.exoplayer2.source.MediaSource;
import com.google.android.exoplayer2.source.TrackGroupArray;
import com.google.android.exoplayer2.trackselection.AdaptiveTrackSelection;
import com.google.android.exoplayer2.trackselection.DefaultTrackSelector;
import com.google.android.exoplayer2.trackselection.MappingTrackSelector.MappedTrackInfo;
import com.google.android.exoplayer2.trackselection.TrackSelection;
import com.google.android.exoplayer2.trackselection.TrackSelectionArray;
import com.google.android.exoplayer2.ui.PlayerControlView;
import com.google.android.exoplayer2.ui.PlayerView;
import com.google.android.exoplayer2.upstream.DataSource;
import com.google.android.exoplayer2.upstream.DefaultBandwidthMeter;
import com.google.android.exoplayer2.upstream.DefaultDataSourceFactory;
import com.google.android.exoplayer2.upstream.DefaultHttpDataSourceFactory;
import com.google.android.exoplayer2.upstream.FileDataSourceFactory;
import com.google.android.exoplayer2.upstream.HttpDataSource;
import com.google.android.exoplayer2.upstream.TransferListener;
import com.google.android.exoplayer2.upstream.cache.Cache;
import com.google.android.exoplayer2.upstream.cache.CacheDataSource;
import com.google.android.exoplayer2.upstream.cache.CacheDataSourceFactory;
import com.google.android.exoplayer2.upstream.cache.NoOpCacheEvictor;
import com.google.android.exoplayer2.upstream.cache.SimpleCache;
import com.google.android.exoplayer2.util.ErrorMessageProvider;
import com.google.android.exoplayer2.util.EventLogger;
import com.google.android.exoplayer2.util.Util;
import com.nineoldandroids.animation.Animator;
import com.nineoldandroids.animation.AnimatorListenerAdapter;
import com.nineoldandroids.animation.ObjectAnimator;

import java.io.File;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.util.Locale;
import java.util.Random;

public class VideoPlayerActivity extends AppCompatActivity implements OnClickListener, PlaybackPreparer, PlayerControlView.VisibilityListener, SwipeInterface {

    public static final String PREFER_EXTENSION_DECODERS_EXTRA = "prefer_extension_decoders";
    private static final String KEY_TRACK_SELECTOR_PARAMETERS = "track_selector_parameters";
    private static final String KEY_WINDOW = "window";
    private static final String KEY_POSITION = "position";
    private static final String KEY_AUTO_PLAY = "auto_play";

    private static final DefaultBandwidthMeter BANDWIDTH_METER = new DefaultBandwidthMeter();
    private static final CookieManager DEFAULT_COOKIE_MANAGER;
    private static final String DOWNLOAD_CONTENT_DIRECTORY = "downloads";

    static {
        DEFAULT_COOKIE_MANAGER = new CookieManager();
        DEFAULT_COOKIE_MANAGER.setCookiePolicy(CookiePolicy.ACCEPT_ORIGINAL_SERVER);
    }

    public int mScreenHeight;
    boolean isShowController;
    AudioManager audioManager;
    ProgressBar mGestureVolumeProgress;
    TextView txt_video_type;
    TextView txt_video_type_detail;
    View lin_notify;
    View lockFrame;
    AppCompatImageView unlockButton;
    AppCompatImageView nextButton;
    AppCompatImageView prevButton;
    int curListPos;
    // Activity lifecycle
    long stopPos = 0;
    GestureDetector mGesDetect;
    private PlayerView playerView;
    private View topBarLayout;
    private TextView titleView;
    private DataSource.Factory mediaDataSourceFactory;
    private SimpleExoPlayer player;
    private MediaSource mediaSource;
    private DefaultTrackSelector trackSelector;
    private DefaultTrackSelector.Parameters trackSelectorParameters;
    private TrackGroupArray lastSeenTrackGroupArray;
    private boolean startAutoPlay;
    private int startWindow;
    private long startPosition;
    private TextView movingMkView;
    private Random random = new Random();
    private static Cache downloadCache;
    private File downloadDirectory;

    private static boolean isBehindLiveWindow(ExoPlaybackException e) {
        if (e.type != ExoPlaybackException.TYPE_SOURCE) {
            return false;
        }
        Throwable cause = e.getSourceException();
        while (cause != null) {
            if (cause instanceof BehindLiveWindowException) {
                return true;
            }
            cause = cause.getCause();
        }
        return false;
    }

    private static CacheDataSourceFactory buildReadOnlyCacheDataSource(
            DefaultDataSourceFactory upstreamFactory, Cache cache) {
        return new CacheDataSourceFactory(
                cache,
                upstreamFactory,
                new FileDataSourceFactory(), null,
                CacheDataSource.FLAG_IGNORE_CACHE_ON_ERROR, null);
    }


    private void mkRandomViewInit() {
        movingMkView = findViewById(R.id.moving_mk_view);
        movingMkView.setText("0000-1111-2222-3333-4444");
        float h = findViewById(R.id.root_view).getHeight();
        movingMkView.setTranslationY(h * random.nextFloat());
        ObjectAnimator anim = ObjectAnimator.ofFloat(movingMkView, "translationX", 3000f, -500f);
        anim.setDuration(40000);
        anim.start();
        anim.setStartDelay(10000);
        anim.addListener(new AnimatorListenerAdapter() {
            @Override
            public void onAnimationCancel(Animator animation) {
                super.onAnimationCancel(animation);
            }

            @Override
            public void onAnimationEnd(Animator animation) {
                super.onAnimationEnd(animation);
                movingMkView.setVisibility(View.GONE);
                mkRandomViewInit();
            }

            @Override
            public void onAnimationRepeat(Animator animation) {
                super.onAnimationRepeat(animation);
            }

            @Override
            public void onAnimationStart(Animator animation) {
                super.onAnimationStart(animation);
                movingMkView.setVisibility(View.VISIBLE);
            }
        });
    }

    private void nextPlay() {
        // TODO: 1/6/2025 consider
//        curListPos++;
//        if (curListPos >= MovieProvider.videoList.size()) curListPos = 0;
//        selVideoPlay(curListPos);
    }

    private void prevPlay() {
//        curListPos--;
//        if (curListPos < 0) curListPos = MovieProvider.videoList.size() - 1;
//        selVideoPlay(curListPos);
    }

    public void selVideoPlay(int position) {
//        VListItem item = MovieProvider.videoList.get(position);
//        int vid = item.getId();
//        int result = 1;
//        for (String path : MovieProvider.arrMountDir) {
//            result = MovieApplication.mWillowLicense.getFiles(path, AppConstant.VALUE_KIND_VIDEO, vid);
//            if (result == 0) break;
//        }
//        if (result == 0) {
//            if (playerView.getController() != null)
//                playerView.getController().clearTimeBarRepeat();
//            player.stop();
//            titleView.setText("item.getTitle()");
//            Uri uri = Uri.parse(MovieApplication.lic_file_paths[0]);
//            String key = MovieApplication.decrypt_key;
//            ExoPlayerFactory.setKey(key);
//            MediaSource mediaSources = buildMediaSource(uri, null);
//            mediaSource = new ConcatenatingMediaSource(mediaSources);
//            player.prepare(mediaSource, true, false);
//        }
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().requestFeature(Window.FEATURE_NO_TITLE);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN, WindowManager.LayoutParams.FLAG_FULLSCREEN);

        mediaDataSourceFactory = buildDataSourceFactory(true);
        if (CookieHandler.getDefault() != DEFAULT_COOKIE_MANAGER) {
            CookieHandler.setDefault(DEFAULT_COOKIE_MANAGER);
        }

        setContentView(R.layout.video_player_activity);
        View rootView = findViewById(R.id.root_view);
        rootView.setOnClickListener(this);

        titleView = findViewById(R.id.title_view);
        topBarLayout = findViewById(R.id.topbar_layout);
        findViewById(R.id.go_back).setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View view) {
                releasePlayer();
                finish();
            }
        });
        mGestureVolumeProgress = findViewById(R.id.progressbar_gesture_volume);
        txt_video_type_detail = findViewById(R.id.txt_video_detail);
        txt_video_type = findViewById(R.id.txt_video_type);
        lin_notify = findViewById(R.id.lin_notify);

        lin_notify.setVisibility(View.GONE);

        playerView = findViewById(R.id.player_view);
        playerView.setControllerVisibilityListener(this);
        playerView.setErrorMessageProvider(new PlayerErrorMessageProvider());
        playerView.requestFocus();
        playerView.setOnClickListener(this);

        lockFrame = findViewById(R.id.top_frame);
        lockFrame.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                unlockButton.setVisibility(View.VISIBLE);
                new Handler().postDelayed(new Runnable() {
                    public void run() {
                        unlockButton.setVisibility(View.GONE);

                    }
                }, 3000);
            }
        });
        lockFrame.setVisibility(View.GONE);

        unlockButton = findViewById(R.id.unlock_btn);

        findViewById(R.id.lock_btn).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                playerView.hideController();
                isShowController = false;
                lockFrame.setVisibility(View.VISIBLE);
                new Handler().postDelayed(new Runnable() {
                    public void run() {
                        unlockButton.setVisibility(View.GONE);

                    }
                }, 3000);
            }
        });
        unlockButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                playerView.showController();
                isShowController = true;
                lockFrame.setVisibility(View.GONE);
            }
        });

        nextButton = findViewById(R.id.next_btn);
        prevButton = findViewById(R.id.prev_btn);
        nextButton.setVisibility(View.VISIBLE);
        prevButton.setVisibility(View.VISIBLE);
        nextButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                nextPlay();
            }
        });
        prevButton.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {
                prevPlay();
            }
        });
        mkRandomViewInit();


        curListPos = 0;
        this.mScreenHeight = getWindowManager().getDefaultDisplay().getWidth();

        mGesDetect = new GestureDetector(this, new DoubleTapGestureDetector());
        ActivitySwipeDetector swipe = new ActivitySwipeDetector(this);
        playerView.setOnTouchListener(swipe);

        if (getIntent().getExtras() != null) {
            titleView.setText("video_title");
        }

        audioManager = (AudioManager) getSystemService(Context.AUDIO_SERVICE);

        int currentVolume = audioManager.getStreamVolume(3);
        this.mGestureVolumeProgress.setMax(2000);
        this.mGestureVolumeProgress.setProgress(currentVolume == 0 ? 0 : currentVolume == 15 ? 2000 : currentVolume * 15);
        setVolumeControlStream(3);
        isShowController = true;

        if (savedInstanceState != null) {
            trackSelectorParameters = savedInstanceState.getParcelable(KEY_TRACK_SELECTOR_PARAMETERS);
            startAutoPlay = savedInstanceState.getBoolean(KEY_AUTO_PLAY);
            startWindow = savedInstanceState.getInt(KEY_WINDOW);
            startPosition = savedInstanceState.getLong(KEY_POSITION);
        } else {
            trackSelectorParameters = new DefaultTrackSelector.ParametersBuilder().build();
            clearStartPosition();
        }
    }

    @Override
    public void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        releasePlayer();
        clearStartPosition();
        setIntent(intent);
    }

    @Override
    public void onStart() {
        super.onStart();
        if (Util.SDK_INT > 23) {
            initializePlayer();
        }
    }

    @Override
    public void onResume() {
        super.onResume();
        if (Util.SDK_INT <= 23 || player == null) {
            initializePlayer();
        }
    }

    // Activity input

    @Override
    public void onPause() {
        super.onPause();
        if (Util.SDK_INT <= 23) {
            releasePlayer();
        }
    }

    // OnClickListener methods

    @Override
    public void onStop() {
        super.onStop();
        if (Util.SDK_INT > 23) {
            releasePlayer();
        }
    }

    // PlaybackControlView.PlaybackPreparer implementation

    @Override
    public void onDestroy() {
        onStop();
        super.onDestroy();
    }

    // PlaybackControlView.VisibilityListener implementation

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions,
                                           @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (grantResults.length == 0) {
            // Empty results are triggered if a permission is requested while another request was already
            // pending and can be safely ignored in this case.
            return;
        }
        if (grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            initializePlayer();
        } else {
            showToast("R.string.storage_permission_denied");
            finish();
        }
    }

    // Internal methods

    @Override
    public void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        updateTrackSelectorParameters();
        updateStartPosition();
        outState.putParcelable(KEY_TRACK_SELECTOR_PARAMETERS, trackSelectorParameters);
        outState.putBoolean(KEY_AUTO_PLAY, startAutoPlay);
        outState.putInt(KEY_WINDOW, startWindow);
        outState.putLong(KEY_POSITION, startPosition);
    }

    @Override
    public boolean dispatchKeyEvent(KeyEvent event) {
        // See whether the player view wants to handle media or DPAD keys events.
        return playerView.dispatchKeyEvent(event) || super.dispatchKeyEvent(event);
    }

    @Override
    public void onClick(View view) {
        int resId = view.getId();
        if (resId == R.id.player_view) {
            if (isShowController) {
                playerView.hideController();
                isShowController = false;
            } else {
                playerView.showController();
                isShowController = true;
            }
        }
    }

    @Override
    public void preparePlayback() {
        initializePlayer();
    }

    private VideoItem item;

    @Override
    public void onVisibilityChange(int visibility) {
        topBarLayout.setVisibility(visibility);
    }

    private void initializePlayer() {
        if (player == null) {
            Intent intent = getIntent();
            item = VideoListActivity.videoList.get(VideoListActivity.selectedPos);
            Uri uri = Uri.fromFile(new File(item.filePath));

            if (Util.maybeRequestReadExternalStoragePermission(this, uri)) {
                return;
            }


            TrackSelection.Factory trackSelectionFactory;
            trackSelectionFactory = new AdaptiveTrackSelection.Factory(BANDWIDTH_METER);

            boolean preferExtensionDecoders =
                    intent.getBooleanExtra(PREFER_EXTENSION_DECODERS_EXTRA, false);
            @DefaultRenderersFactory.ExtensionRendererMode int extensionRendererMode =
                    (preferExtensionDecoders ? DefaultRenderersFactory.EXTENSION_RENDERER_MODE_PREFER
                            : DefaultRenderersFactory.EXTENSION_RENDERER_MODE_ON);
            DefaultRenderersFactory renderersFactory =
                    new DefaultRenderersFactory(this, extensionRendererMode);

            trackSelector = new DefaultTrackSelector(trackSelectionFactory);
            trackSelector.setParameters(trackSelectorParameters);
            lastSeenTrackGroupArray = null;

            player = ExoPlayerFactory.newSimpleInstance(renderersFactory, trackSelector, null, "key");
            player.addListener(new PlayerEventListener());
            player.setPlayWhenReady(startAutoPlay);
            player.addAnalyticsListener(new EventLogger(trackSelector));
            playerView.setPlayer(player);
            playerView.setPlaybackPreparer(this);

            MediaSource mediaSources = new ExtractorMediaSource.Factory(mediaDataSourceFactory).createMediaSource(uri);
            mediaSource = new ConcatenatingMediaSource(mediaSources);
        }
        boolean haveStartPosition = startWindow != C.INDEX_UNSET;
        if (haveStartPosition) {
            player.seekTo(startWindow, startPosition);
        }
        player.prepare(mediaSource, !haveStartPosition, false);
    }

    private void releasePlayer() {
        if (player != null) {
            updateTrackSelectorParameters();
            updateStartPosition();
            player.release();
            player = null;
            mediaSource = null;
            trackSelector = null;
        }
    }

    private void updateTrackSelectorParameters() {
        if (trackSelector != null) {
            trackSelectorParameters = trackSelector.getParameters();
        }
    }

    private void updateStartPosition() {
        if (player != null) {
            startAutoPlay = player.getPlayWhenReady();
            startWindow = player.getCurrentWindowIndex();
            startPosition = Math.max(0, player.getContentPosition());
        }
    }

    private void clearStartPosition() {
        startAutoPlay = true;
        startWindow = C.INDEX_UNSET;
        startPosition = C.TIME_UNSET;
    }

    public HttpDataSource.Factory buildHttpDataSourceFactory(
            TransferListener<? super DataSource> listener) {
        return new DefaultHttpDataSourceFactory(Util.getUserAgent(this, "Willow"), listener);
    }

    public DataSource.Factory buildDataSourceFactory(TransferListener<? super DataSource> listener) {
        DefaultDataSourceFactory upstreamFactory = new DefaultDataSourceFactory(this, listener, buildHttpDataSourceFactory(listener));
        return buildReadOnlyCacheDataSource(upstreamFactory, getDownloadCache());
    }

    private File getDownloadDirectory() {
        if (downloadDirectory == null) {
            downloadDirectory = getExternalFilesDir(null);
            if (downloadDirectory == null) {
                downloadDirectory = getFilesDir();
            }
        }
        return downloadDirectory;
    }

    private synchronized Cache getDownloadCache() {
        if (downloadCache == null) {
            File downloadContentDirectory = new File(getDownloadDirectory(), DOWNLOAD_CONTENT_DIRECTORY);
            downloadCache = new SimpleCache(downloadContentDirectory, new NoOpCacheEvictor());
        }
        return downloadCache;
    }

    private DataSource.Factory buildDataSourceFactory(boolean useBandwidthMeter) {
        return buildDataSourceFactory(useBandwidthMeter ? BANDWIDTH_METER : null);
    }

    private void showControls() {
        topBarLayout.setVisibility(View.VISIBLE);
    }


    private void showToast(String message) {
        Toast.makeText(getApplicationContext(), message, Toast.LENGTH_SHORT).show();
    }

    @Override
    public void bottom2top(View v, float deltaY) {
        lin_notify.setVisibility(View.GONE);
    }

    @Override
    public void left2right(View v, float deltaX) {
        if (v.getId() == R.id.player_view) {
            long time = (long) (player.getCurrentPosition() + Math.abs(deltaX) * 10);
            fastForward(time);
        }
    }

    @Override
    public void right2left(View v, float deltaX) {
        if (v.getId() == R.id.player_view) {
            long time = (long) (player.getCurrentPosition() - Math.abs(deltaX) * 10);
            rewind(time);
        }
    }

    @Override
    public void top2bottom(View v, float deltaY) {
        lin_notify.setVisibility(View.GONE);
    }

    @Override
    public void bottom2topMove(View v, float deltaY) {
        updateGestureVolume(deltaY);
    }

    @Override
    public void left2rightMove(View v, float deltaX) {
        if (v.getId() == R.id.player_view) {
            long time = (long) (player.getCurrentPosition() + Math.abs(deltaX) * 10);
            display_video_time(time);
        }
    }

    @Override
    public void right2leftMove(View v, float deltaX) {
        if (v.getId() == R.id.player_view) {
            long time = (long) (player.getCurrentPosition() - Math.abs(deltaX) * 10);
            display_video_time(time);
        }
    }

    @Override
    public void top2bottomMove(View v, float deltaY) {
        updateGestureVolume(deltaY);
    }

    @Override
    public void onClickView(View v) {

        if (!playerView.controller.controllerViewStatus) isShowController = false;

        lin_notify.setVisibility(View.GONE);
        if (isShowController) {
            playerView.hideController();
            isShowController = false;
        } else {
            playerView.showController();
            isShowController = true;
        }

    }

    @Override
    public boolean onTouch(View v, MotionEvent event) {
        if (player != null
                && player.getPlaybackState() != Player.STATE_ENDED
                && player.getPlaybackState() != Player.STATE_IDLE
                && player.getPlayWhenReady()) {
            Log.d("mcnup", "Double Tap Stop ...");
            stopPos = player.getCurrentPosition();
            player.stop();
            com.google.android.exoplayer2.ui.PlayerControlView.doubleTapStatus = true;
            com.google.android.exoplayer2.ui.PlayerControlView.doubleTapStopPos = stopPos;
        } else {
            Log.d("mcnup", "Double Tap Play ...");
            playerView.getController().getPlaybackPreparer().preparePlayback();
            player.seekTo(stopPos);
            com.google.android.exoplayer2.ui.PlayerControlView.doubleTapStatus = false;
        }
        return true;
    }

    public void display_video_time(long time) {
        lin_notify.setVisibility(View.VISIBLE);
        int secondsUntilFinished = (int) time / 1000;

        int seconds = secondsUntilFinished % 60;
        int mins = secondsUntilFinished / 60;
        String text = String.format(Locale.getDefault(), "%02d : %02d",
                mins,
                seconds);

        txt_video_type.setText("시간");
        txt_video_type_detail.setText(text);
    }

    public void updateGestureVolume(float delta) {
        if (ActivitySwipeDetector.currentX > this.mScreenHeight / 2) {
            lin_notify.setVisibility(View.VISIBLE);
            float dY = 2000.0f;
            float dY2 = ((float) this.mGestureVolumeProgress.getProgress()) + ((delta / 10 / ((float) this.mScreenHeight)) * 2000.0f);
            if (dY2 < 0.05f) {
                dY = 0.0f;
            } else if (dY2 <= 2000.0f) {
                dY = dY2;
            }
            this.mGestureVolumeProgress.setProgress(Math.round(dY));
            txt_video_type.setText("음량");
            txt_video_type_detail.setText(Math.round(dY) / 20 + "%");
            audioManager.setStreamVolume(3, Math.round(dY) / 133, 0);
        } else {
            lin_notify.setVisibility(View.VISIBLE);
            float dY = 2000.0f;
            float dY2 = ((float) this.mGestureVolumeProgress.getProgress()) + ((delta / 10 / ((float) this.mScreenHeight)) * 2000.0f);
            if (dY2 < 0.05f) {
                dY = 0.0f;
            } else if (dY2 <= 2000.0f) {
                dY = dY2;
            }
            this.mGestureVolumeProgress.setProgress(Math.round(dY));
            txt_video_type.setText("밝기");
            txt_video_type_detail.setText((Math.round(dY) / 20 > 100 ? 100 : (Math.round(dY) / 20)) + "%");
            WindowManager.LayoutParams lp = getWindow().getAttributes();
            lp.screenBrightness = (Math.round(dY) / 20 > 100 ? 100 : (Math.round(dY) / 20)) / 100.0f;
            getWindow().setAttributes(lp);

        }
    }


    private void rewind(long time) {
        if (time <= 0) {
            return;
        }
        player.seekTo(Math.max(time, 0));
        lin_notify.setVisibility(View.GONE);
    }

    private void fastForward(long time) {
        if (time <= 0) {
            return;
        }
        long durationMs = player.getDuration();
        long seekPositionMs = time;
        if (durationMs != C.TIME_UNSET) {
            seekPositionMs = Math.min(seekPositionMs, durationMs);
        }
        player.seekTo(seekPositionMs);
        lin_notify.setVisibility(View.GONE);
    }

    private static class DoubleTapGestureDetector extends GestureDetector.SimpleOnGestureListener {

        @Override
        public boolean onDoubleTap(MotionEvent e) {
            Log.d("TAG", "Double Tap Detected ...");
            return true;
        }
    }

    private class PlayerEventListener extends Player.DefaultEventListener {

        @Override
        public void onPlayerStateChanged(boolean playWhenReady, int playbackState) {
            if (playbackState == Player.STATE_ENDED) {
                nextPlay();
//                showControls();
            }

        }

        @Override
        public void onPositionDiscontinuity(@Player.DiscontinuityReason int reason) {
            if (player.getPlaybackError() != null) {
                // The user has performed a seek whilst in the error state. Update the resume position so
                // that if the user then retries, playback resumes from the position to which they seeked.
                updateStartPosition();
            }
        }

        @Override
        public void onPlayerError(ExoPlaybackException e) {
            if (isBehindLiveWindow(e)) {
                clearStartPosition();
                initializePlayer();
            } else {
                updateStartPosition();
                showControls();
            }
        }

        @Override
        @SuppressWarnings("ReferenceEquality")
        public void onTracksChanged(TrackGroupArray trackGroups, TrackSelectionArray trackSelections) {
//            updateButtonVisibilities();
            if (trackGroups != lastSeenTrackGroupArray) {
                MappedTrackInfo mappedTrackInfo = trackSelector.getCurrentMappedTrackInfo();
                if (mappedTrackInfo != null) {
                    if (mappedTrackInfo.getTypeSupport(C.TRACK_TYPE_VIDEO)
                            == MappedTrackInfo.RENDERER_SUPPORT_UNSUPPORTED_TRACKS) {
                        showToast("R.string.error_unsupported_video");
                    }
                    if (mappedTrackInfo.getTypeSupport(C.TRACK_TYPE_AUDIO)
                            == MappedTrackInfo.RENDERER_SUPPORT_UNSUPPORTED_TRACKS) {
                        showToast("R.string.error_unsupported_audio");
                    }
                }
                lastSeenTrackGroupArray = trackGroups;
            }
        }
    }

    private class PlayerErrorMessageProvider implements ErrorMessageProvider<ExoPlaybackException> {

        @Override
        public Pair<Integer, String> getErrorMessage(ExoPlaybackException e) {
            String errorString = "getString(R.string.error_generic)";
            if (e.type == ExoPlaybackException.TYPE_RENDERER) {
                Exception cause = e.getRendererException();
                if (cause instanceof DecoderInitializationException) {
                    errorString = "getString(R.string.error_querying_decoders)";
                }
            }
            return Pair.create(0, errorString);
        }
    }
}

