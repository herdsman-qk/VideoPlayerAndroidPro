package com.dev.kee.video;

import android.view.MotionEvent;
import android.view.View;

public interface SwipeInterface {
    void bottom2top(View v, float deltaY);

    void left2right(View v, float deltaX);

    void right2left(View v, float deltaX);

    void top2bottom(View v, float deltaY);

    void bottom2topMove(View v, float deltaY);

    void left2rightMove(View v, float deltaX);

    void right2leftMove(View v, float deltaX);

    void top2bottomMove(View v, float deltaY);

    void onClickView(View v);

    boolean onTouch(View v, MotionEvent event);
}
