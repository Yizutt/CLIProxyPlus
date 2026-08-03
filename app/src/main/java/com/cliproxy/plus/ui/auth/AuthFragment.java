package com.cliproxy.plus.ui.auth;

import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.cardview.widget.CardView;
import androidx.fragment.app.Fragment;
import com.cliproxy.plus.management.ManagementAPIClient;
import com.cliproxy.plus.config.ConfigManager;
import android.os.Handler;
import android.os.Looper;

import com.cliproxy.plus.config.ConfigManager;
import com.cliproxy.plus.management.ManagementAPIClient;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Auth Files - 账号管理
 */
public class AuthFragment extends Fragment {

    private LinearLayout root;
    private ManagementAPIClient apiClient;

    @Nullable
    @Override
    public ViewGroup onCreateView(@NonNull android.view.LayoutInflater inflater,
                                   @Nullable ViewGroup container,
                                   @Nullable Bundle savedInstanceState) {
        ScrollView scroll = new ScrollView(requireContext());
        scroll.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
        scroll.setBackgroundColor(0xFF1E1E2E);
        scroll.setPadding(16, 16, 16, 16);

        root = new LinearLayout(requireContext());
        root.setOrientation(LinearLayout.VERTICAL);
        root.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));

        // 标题
        root.addView(makeTitle("Auth Files"));

        // 加载中占位
        root.addView(makeCard("Auth Files", makeInfoRow("状态", "加载中...")));

        // 使用说明
        root.addView(makeCard("使用说明",
            makeInfoRow("\u25B6 OAuth", "在 OAuth 标签页发起登录"),
            makeInfoRow("\u25B6 API Key", "在 API Keys 标签页添加密钥"),
            makeInfoRow("\u25B6 管理", "在 Config 标签页查看配置")));

        scroll.addView(root);

        // 在后台线程加载数据
        int port = ConfigManager.getInstance().getInt("port", 8317);
        apiClient = new ManagementAPIClient("http://127.0.0.1:" + port);
        loadAuthFiles();

        return scroll;
    }

    private void loadAuthFiles() {
        new Thread(() -> {
            try {
                JSONArray files = apiClient.listAuthFiles();
                Handler mainHandler = new Handler(Looper.getMainLooper());
                mainHandler.post(() -> populateAuthFiles(files));
            } catch (Exception e) {
                Handler mainHandler = new Handler(Looper.getMainLooper());
                mainHandler.post(() -> {
                    // 替换第一个卡片为错误信息
                    root.removeViewAt(1);
                    root.addView(makeCard("Auth Files",
                        makeInfoRow("错误", "加载失败: " + e.getMessage())), 1);
                });
            }
        }).start();
    }

    private void populateAuthFiles(JSONArray files) {
        // 移除加载中的卡片
        root.removeViewAt(1);

        if (files == null || files.length() == 0) {
            root.addView(makeCard("Auth Files", makeInfoRow("状态", "暂无认证文件")), 1);
            return;
        }

        LinearLayout[] rows = new LinearLayout[files.length()];
        for (int i = 0; i < files.length(); i++) {
            JSONObject file = files.optJSONObject(i);
            if (file != null) {
                String name = file.optString("name", "未知");
                String provider = file.optString("provider", "未知");
                rows[i] = makeInfoRow(name, provider);
            } else {
                // 如果数组元素是纯字符串（文件名）
                rows[i] = makeInfoRow("文件", files.optString(i, "未知"));
            }
        }
        root.addView(makeCard("Auth Files (" + files.length() + ")", rows), 1);
    }

    private TextView makeTitle(String t) {
        TextView tv = new TextView(requireContext());
        tv.setText(t);
        tv.setTextSize(24);
        tv.setTextColor(0xFFF5C2E7);
        tv.setTypeface(null, Typeface.BOLD);
        tv.setPadding(0, 0, 0, 16);
        return tv;
    }

    private CardView makeCard(String title, LinearLayout... rows) {
        CardView card = new CardView(requireContext());
        LinearLayout.LayoutParams mp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        mp.setMargins(0, 0, 0, 12);
        card.setLayoutParams(mp);
        card.setCardBackgroundColor(0xFF313244);
        card.setRadius(12);
        card.setCardElevation(4);
        card.setUseCompatPadding(true);

        LinearLayout content = new LinearLayout(requireContext());
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(16, 16, 16, 16);

        TextView titleView = new TextView(requireContext());
        titleView.setText(title);
        titleView.setTextSize(16);
        titleView.setTextColor(0xFF3B82F6);
        titleView.setTypeface(null, Typeface.BOLD);
        titleView.setPadding(0, 0, 0, 8);
        content.addView(titleView);

        for (LinearLayout row : rows) {
            content.addView(row);
        }
        card.addView(content);
        return card;
    }

    private LinearLayout makeInfoRow(String label, String value) {
        LinearLayout row = new LinearLayout(requireContext());
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setPadding(0, 4, 0, 4);

        TextView labelView = new TextView(requireContext());
        labelView.setText(label);
        labelView.setTextSize(13);
        labelView.setTextColor(0xFF7C3AED);
        labelView.setTypeface(null, Typeface.BOLD);
        labelView.setPadding(0, 0, 8, 0);

        TextView valueView = new TextView(requireContext());
        valueView.setText(value);
        valueView.setTextSize(13);
        valueView.setTextColor(0xFFCDD6F4);

        row.addView(labelView);
        row.addView(valueView);
        return row;
    }
}