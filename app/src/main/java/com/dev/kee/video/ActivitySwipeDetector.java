package com.dev.kee.video;

import android.util.Log;
import android.view.MotionEvent;
import android.view.View;

public class ActivitySwipeDetector implements View.OnTouchListener {

    static final String logTag = "ActivitySwipeDetector";
    static final int MIN_DISTANCE = 100;
    static final int MIN_DISTANCE_VOL = 20;
    static final int MAX_DURATION = 500;
    public static float currentX = -1;
    int clickCount = 0;
    long startTime, endTime;
    long duration;
    private final SwipeInterface activity;
    private float downX, downY, upX, upY;

    public ActivitySwipeDetector(SwipeInterface activity) {
        this.activity = activity;
    }

    public void onRightToLeftSwipe(View v, float deltaX) {
        Log.i(logTag, "RightToLeftSwipe!");
        activity.right2left(v, deltaX);
    }

    public void onLeftToRightSwipe(View v, float deltaX) {
        Log.i(logTag, "LeftToRightSwipe!");
        activity.left2right(v, deltaX);
    }

    public void onTopToBottomSwipe(View v, float deltaY) {
        Log.i(logTag, "onTopToBottomSwipe!");
        activity.top2bottom(v, deltaY);
    }

    public void onBottomToTopSwipe(View v, float deltaY) {
        Log.i(logTag, "onBottomToTopSwipe!");
        activity.bottom2top(v, deltaY);
    }

    public void onRightToLeftSwipeMove(View v, float deltaX) {
        Log.i(logTag, "RightToLeftSwipe!");
        activity.right2leftMove(v, deltaX);
    }

    public void onLeftToRightSwipeMove(View v, float deltaX) {
        Log.i(logTag, "LeftToRightSwipe!");
        activity.left2rightMove(v, deltaX);
    }

    public void onTopToBottomSwipeMove(View v, float deltaY) {
        Log.i(logTag, "onTopToBottomSwipe!");
        activity.top2bottomMove(v, deltaY);
    }

    public void onBottomToTopSwipeMove(View v, float deltaY) {
        Log.i(logTag, "onBottomToTopSwipe!");
        activity.bottom2topMove(v, deltaY);
    }

    public void onClickView(View v) {
        Log.i(logTag, "onBottomToTopSwipe!");
        activity.onClickView(v);
    }

    public boolean onTouch(View v, MotionEvent event) {

        switch (event.getAction() & MotionEvent.ACTION_MASK) {
            case MotionEvent.ACTION_DOWN: {
                downX = event.getX();
                downY = event.getY();
                currentX = downX;

                if (clickCount == 0) {
                    startTime = System.currentTimeMillis();
                } else if (clickCount == 1) {
                    endTime = System.currentTimeMillis();
                    //Double tap code by mcn
                }

                clickCount++;

                return true;
            }
            case MotionEvent.ACTION_MOVE: {
                upX = event.getX();
                upY = event.getY();

                float deltaX = downX - upX;
                float deltaY = downY - upY;

                // swipe horizontal?
                if (Math.abs(deltaX) > MIN_DISTANCE) {
                    // left or right
                    if (deltaX < 0) {
                        this.onLeftToRightSwipeMove(v, deltaX);
                        return true;
                    }
                    if (deltaX > 0) {
                        this.onRightToLeftSwipeMove(v, deltaX);
                        return true;
                    }
                }

                // swipe vertical?
                if (Math.abs(deltaY) > MIN_DISTANCE_VOL) {
                    // top or down
                    if (deltaY < 0) {
                        this.onTopToBottomSwipeMove(v, deltaY);
                        return true;
                    }
                    if (deltaY > 0) {
                        this.onBottomToTopSwipeMove(v, deltaY);
                        return true;
                    }
                }

                return true;
            }

            case MotionEvent.ACTION_UP: {
                upX = event.getX();
                upY = event.getY();

                float deltaX = downX - upX;
                float deltaY = downY - upY;

                if (startTime != 0 && endTime != 0 && (endTime - startTime) > MAX_DURATION) {
                    startTime = endTime;
                    clickCount = 1;
                }
                if (clickCount == 2) {
                    duration = endTime - startTime;

                    if (duration <= MAX_DURATION) {
                        activity.onTouch(v, event);
                        clickCount = 0;
                        duration = 0;
                        return true;
                    }
                    clickCount = 0;
                    duration = 0;
                }
                // swipe horizontal?
                if (Math.abs(deltaX) > MIN_DISTANCE) {
                    // left or right
                    if (deltaX < 0) {
                        this.onLeftToRightSwipe(v, deltaX);
                        return true;
                    }
                    if (deltaX > 0) {
                        this.onRightToLeftSwipe(v, deltaX);
                        return true;
                    }
                } else {
                    onClickView(v);
                    return true;
                }

                // swipe vertical?
                if (Math.abs(deltaY) > MIN_DISTANCE) {
                    // top or down
                    if (deltaY < 0) {
                        this.onTopToBottomSwipe(v, deltaY);
                        return true;
                    }
                    if (deltaY > 0) {
                        this.onBottomToTopSwipe(v, deltaY);
                        return true;
                    }
                } else {
                    onClickView(v);
                    return true;
                }
                return true;
            }

        }
        activity.onTouch(v, event);
        return false;
    }

}
