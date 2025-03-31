package com.dev.kee.video;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.RecyclerView;

import android.content.Intent;
import android.graphics.BitmapFactory;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.preference.PreferenceManager;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import com.dev.videoandpdf.R;
import com.google.gson.Gson;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FilenameFilter;
import java.util.ArrayList;

public class VideoListActivity extends AppCompatActivity {

    public static ArrayList<VideoItem> videoList = new ArrayList<>();
    public static int selectedPos = -1;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_video_list);

        initAll();

    }

    private void initVideoList() {
        videoList.clear();

        String listJsonData = PreferenceManager.getDefaultSharedPreferences(this).getString("data", "");
        VideoItem[] data = new Gson().fromJson(listJsonData, VideoItem[].class);
        if (data != null) {
            for (VideoItem item : data) {
                videoList.add(item);
            }
        }

//        // start test
//        VideoItem item = new VideoItem();
//        item.title = "hhh";
//        item.filePath = new File(Environment.getExternalStorageDirectory(), "Pictures/1_enc.mp4").getAbsolutePath();
//        //end test

//        videoList.add(item);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.option_menu, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (item.getItemId() == R.id.update_file_list) {
            updateFileList();
        }
        return super.onOptionsItemSelected(item);
    }

    private void updateFileList() {
        File dir = new File(Environment.getExternalStorageDirectory(), FILES_DIR);
        File[] files = dir.listFiles(new FilenameFilter() {
            @Override
            public boolean accept(File file, String s) {
                return s.contains(".mp4");
            }
        });

        videoList.clear();

        for (File file : files) {
            VideoItem newItem = KeEVideoUtils.parseFile(file.getAbsolutePath());
            Log.d("kee_log", new Gson().toJson(newItem));
            newItem.filePath = file.getAbsolutePath();
            videoList.add(newItem);
        }

        VideoItem[] data = videoList.toArray(new VideoItem[]{});
        String jsonListData = new Gson().toJson(data);
        PreferenceManager.getDefaultSharedPreferences(this).edit().putString("data", jsonListData).apply();

        ((VideoAdapter) ((RecyclerView) findViewById(R.id.recycler_view)).getAdapter()).notifyDataSetChanged();

        Toast.makeText(this, "finished", Toast.LENGTH_SHORT).show();
    }

    public static final String FILES_DIR = "Pictures";

    private void initAll() {

        File dir = new File(Environment.getExternalStorageDirectory(), FILES_DIR);
        dir.mkdir();
        dir.mkdirs();

//        getSupportActionBar()

        initVideoList();

        VideoAdapter adapter = new VideoAdapter();
        adapter.setOnItemClicked(new VideoAdapter.OnItemClicked() {
            @Override
            public void onClicked(int pos) {
                selectedPos = pos;
                startActivity(new Intent(getBaseContext(), VideoPlayerActivity.class));
            }
        });
        ((RecyclerView) findViewById(R.id.recycler_view)).setAdapter(adapter);
    }

    public static class VideoAdapter extends RecyclerView.Adapter<VideoAdapter.Holder> {

        private OnItemClicked onItemClicked = null;

        public void setOnItemClicked(OnItemClicked l) {
            onItemClicked = l;
        }

        @NonNull
        @Override
        public Holder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.video_item_layout, parent, false);
            return new Holder(view);
        }

        @Override
        public void onBindViewHolder(@NonNull Holder holder, int position) {
            VideoItem item = videoList.get(position);
            ((TextView) holder.itemView.findViewById(R.id.title_view)).setText(item.title);

            ((ImageView) holder.itemView.findViewById(R.id.thumb_view)).setImageBitmap(BitmapFactory.decodeStream(new ByteArrayInputStream( KeEVideoUtils.getThumb(item.filePath, item.thumbLen))));

            holder.itemView.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View view) {
                    if (onItemClicked != null) {
                        onItemClicked.onClicked(position);
                    }
                }
            });
        }

        @Override
        public int getItemCount() {
            return videoList.size();
        }

        interface OnItemClicked {
            void onClicked(int pos);
        }

        protected static class Holder extends RecyclerView.ViewHolder {

            public Holder(@NonNull View itemView) {
                super(itemView);
            }
        }
    }
}