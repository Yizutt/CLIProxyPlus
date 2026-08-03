package com.cliproxy.plus.ui.config;

import android.graphics.Color;
import android.os.Bundle;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.cardview.widget.CardView;
import androidx.fragment.app.Fragment;

import com.cliproxy.plus.config.ConfigManager;

import org.json.JSONObject;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * ConfigFragment - 配置管理 (纯 Java UI)
 * 显示 YAML/JSON 配置，支持编辑、保存、重载
 */
public class ConfigFragment extends Fragment {

    private static final String TAG = "ConfigFragment";

    private TextView configContentText;
    private TextView statusText;
    private TextView lastSavedText;
    private LinearLayout root;
    private String currentConfigYaml = "";
    private String currentConfigJson = "";

    @Nullable
    @Override
    public View onCreateView(@NonNull android.view.LayoutInflater inflater,
                              @Nullable ViewGroup container,
                              @Nullable Bundle savedInstanceState) {
        ScrollView scrollView = new ScrollView(requireContext());
        scrollView.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
        scrollView.setPadding(16, 16, 16, 16);
        scrollView.setBackgroundColor(Color.parseColor("#1E1E2E"));

        root = new LinearLayout(requireContext());
        root.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        root.setOrientation(LinearLayout.VERTICAL);

        // 标题
        root.addView(createTitle("配置管理"));

        // 状态卡片
        statusText = new TextView(requireContext());
        lastSavedText = new TextView(requireContext());
        root.addView(createCard("配置状态", statusText, lastSavedText));

        // 操作按钮栏
        root.addView(createActionBar());

        // 配置内容卡片
        configContentText = new TextView(requireContext());
        configContentText.setTextSize(13);
        configContentText.setTextColor(Color.parseColor("#CDD6F4"));
        configContentText.setTypeface(android.graphics.Typeface.MONOSPACE);
        configContentText.setPadding(0, 0, 0, 0);

        CardView configCard = createCard("配置内容", configContentText);
        root.addView(configCard);

        scrollView.addView(root);
        return scrollView;
    }

    @Override
    public void onResume() {
        super.onResume();
        refreshConfig();
    }

    // ── 标题 ────────────────────────────────────────────────

    private TextView createTitle(String text) {
        TextView tv = new TextView(requireContext());
        tv.setText(text);
        tv.setTextSize(24);
        tv.setTextColor(Color.parseColor("#F5C2E7"));
        tv.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        tv.setPadding(0, 0, 0, 16);
        return tv;
    }

    // ── 操作按钮栏 ──────────────────────────────────────────

    private LinearLayout createActionBar() {
        LinearLayout bar = new LinearLayout(requireContext());
        bar.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setPadding(0, 0, 0, 16);

        // 编辑按钮
        Button editButton = new Button(requireContext());
        LinearLayout.LayoutParams editParams = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f);
        editParams.setMargins(0, 0, 8, 0);
        editButton.setLayoutParams(editParams);
        editButton.setText("✎ 编辑配置");
        editButton.setTextColor(Color.parseColor("#FFFFFF"));
        editButton.setBackgroundColor(Color.parseColor("#7C3AED"));
        editButton.setPadding(12, 10, 12, 10);
        editButton.setAllCaps(false);
        editButton.setTextSize(14);
        editButton.setOnClickListener(v -> showEditDialog());

        // 保存按钮
        Button saveButton = new Button(requireContext());
        LinearLayout.LayoutParams saveParams = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f);
        saveParams.setMargins(8, 0, 8, 0);
        saveButton.setLayoutParams(saveParams);
        saveButton.setText("💾 保存");
        saveButton.setTextColor(Color.parseColor("#FFFFFF"));
        saveButton.setBackgroundColor(Color.parseColor("#22C55E"));
        saveButton.setPadding(12, 10, 12, 10);
        saveButton.setAllCaps(false);
        saveButton.setTextSize(14);
        saveButton.setOnClickListener(v -> saveConfig());

        // 重载按钮
        Button reloadButton = new Button(requireContext());
        LinearLayout.LayoutParams reloadParams = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f);
        reloadParams.setMargins(8, 0, 0, 0);
        reloadButton.setLayoutParams(reloadParams);
        reloadButton.setText("⟳ 重载");
        reloadButton.setTextColor(Color.parseColor("#CDD6F4"));
        reloadButton.setBackgroundColor(Color.parseColor("#45475A"));
        reloadButton.setPadding(12, 10, 12, 10);
        reloadButton.setAllCaps(false);
        reloadButton.setTextSize(14);
        reloadButton.setOnClickListener(v -> reloadConfig());

        bar.addView(editButton);
        bar.addView(saveButton);
        bar.addView(reloadButton);

        return bar;
    }

    // ── 卡片 ────────────────────────────────────────────────

    private CardView createCard(String title, TextView... lines) {
        CardView card = new CardView(requireContext());
        LinearLayout.LayoutParams cardParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        cardParams.setMargins(0, 0, 0, 12);
        card.setLayoutParams(cardParams);
        card.setCardBackgroundColor(Color.parseColor("#313244"));
        card.setRadius(12);
        card.setCardElevation(4);
        card.setUseCompatPadding(true);

        LinearLayout content = new LinearLayout(requireContext());
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(16, 16, 16, 16);

        TextView titleView = new TextView(requireContext());
        titleView.setText(title);
        titleView.setTextSize(18);
        titleView.setTextColor(Color.parseColor("#7C3AED"));
        titleView.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        titleView.setPadding(0, 0, 0, 8);
        content.addView(titleView);

        // 分隔线
        View divider = new View(requireContext());
        LinearLayout.LayoutParams divParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 1);
        divParams.setMargins(0, 0, 0, 10);
        divider.setLayoutParams(divParams);
        divider.setBackgroundColor(Color.parseColor("#45475A"));
        content.addView(divider);

        for (TextView line : lines) {
            line.setTextSize(15);
            line.setPadding(0, 2, 0, 2);
            content.addView(line);
        }

        card.addView(content);
        return card;
    }

    // ── 编辑对话框 ──────────────────────────────────────────

    private void showEditDialog() {
        android.app.AlertDialog.Builder builder = new android.app.AlertDialog.Builder(requireContext());
        builder.setTitle("编辑配置");

        LinearLayout dialogLayout = new LinearLayout(requireContext());
        dialogLayout.setOrientation(LinearLayout.VERTICAL);
        dialogLayout.setPadding(24, 16, 24, 16);

        // 提示文字
        TextView hintText = new TextView(requireContext());
        hintText.setText("以 JSON 格式编辑配置，修改后点击保存即可生效：");
        hintText.setTextSize(13);
        hintText.setTextColor(Color.parseColor("#A6ADC8"));
        hintText.setPadding(0, 0, 0, 12);
        dialogLayout.addView(hintText);

        // 编辑框
        final EditText editorInput = new EditText(requireContext());
        editorInput.setText(currentConfigJson);
        editorInput.setTextColor(Color.parseColor("#CDD6F4"));
        editorInput.setHintTextColor(Color.parseColor("#6C7086"));
        editorInput.setBackgroundColor(Color.parseColor("#1E1E2E"));
        editorInput.setPadding(12, 12, 12, 12);
        editorInput.setTextSize(12);
        editorInput.setTypeface(android.graphics.Typeface.MONOSPACE);
        editorInput.setGravity(Gravity.TOP);
        editorInput.setMinLines(16);
        editorInput.setMaxLines(24);
        editorInput.setHorizontalScrollBarEnabled(true);
        editorInput.setVerticalScrollBarEnabled(true);

        LinearLayout.LayoutParams editorParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        editorInput.setLayoutParams(editorParams);

        // 给编辑框加一个边框效果
        editorInput.setBackgroundColor(Color.parseColor("#1E1E2E"));
        editorInput.setPadding(12, 12, 12, 12);

        dialogLayout.addView(editorInput);

        builder.setView(dialogLayout);

        builder.setPositiveButton("保存", (dialog, which) -> {
            String editedJson = editorInput.getText().toString().trim();
            if (editedJson.isEmpty()) {
                Toast.makeText(requireContext(), "配置内容不能为空", Toast.LENGTH_SHORT).show();
                return;
            }
            applyEditedConfig(editedJson);
        });

        builder.setNegativeButton("取消", null);
        builder.show();
    }

    // ── 配置操作 ────────────────────────────────────────────

    private void refreshConfig() {
        try {
            ConfigManager config = getConfigManager();
            if (config == null) {
                setStatusText("⚫ 未初始化", "#F38BA8");
                setText(lastSavedText, "ConfigManager 尚未初始化", "#6C7086");
                return;
            }

            // 读取当前配置
            currentConfigJson = config.getConfigJson();
            currentConfigYaml = config.exportYaml();

            // 格式化为更易读的 JSON
            try {
                JSONObject jsonObj = new JSONObject(currentConfigJson);
                currentConfigJson = jsonObj.toString(2);
            } catch (Exception ignored) {
                // 保持原样
            }

            // 显示配置内容（优先显示 YAML 风格，没有则显示 JSON）
            if (currentConfigYaml != null && !currentConfigYaml.isEmpty() && !currentConfigYaml.startsWith("# CLIProxy")) {
                configContentText.setText(currentConfigYaml);
            } else {
                configContentText.setText(currentConfigJson);
            }

            // 解析关键状态
            int port = config.getInt("port", 8317);
            boolean debug = config.getBoolean("debug", false);
            String host = config.getString("host", "");

            StringBuilder status = new StringBuilder();
            status.append("🟢 配置已加载");
            if (debug) status.append(" | 调试模式");
            if (!host.isEmpty()) status.append(" | 主机: ").append(host);
            status.append(" | 端口: ").append(port);

            setStatusText(status.toString(), "#22C55E");

            String timeStr = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
                    .format(new Date());
            setText(lastSavedText, "最后刷新: " + timeStr, "#A6ADC8");

            Log.d(TAG, "Config refreshed: " + currentConfigJson);

        } catch (Exception e) {
            Log.e(TAG, "Error refreshing config", e);
            setStatusText("🔴 配置加载失败: " + e.getMessage(), "#F38BA8");
        }
    }

    private void saveConfig() {
        try {
            ConfigManager config = getConfigManager();
            if (config == null) {
                Toast.makeText(requireContext(), "ConfigManager 未初始化", Toast.LENGTH_SHORT).show();
                return;
            }

            config.saveConfig();
            setText(lastSavedText, "最后保存: " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss",
                    Locale.getDefault()).format(new Date()), "#A6ADC8");
            Toast.makeText(requireContext(), "配置已保存", Toast.LENGTH_SHORT).show();
            Log.i(TAG, "Config saved");

        } catch (Exception e) {
            Log.e(TAG, "Error saving config", e);
            Toast.makeText(requireContext(), "保存失败: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void reloadConfig() {
        try {
            ConfigManager config = getConfigManager();
            if (config == null) {
                Toast.makeText(requireContext(), "ConfigManager 未初始化", Toast.LENGTH_SHORT).show();
                return;
            }

            config.reload();
            refreshConfig();
            Toast.makeText(requireContext(), "配置已重载", Toast.LENGTH_SHORT).show();
            Log.i(TAG, "Config reloaded");

        } catch (Exception e) {
            Log.e(TAG, "Error reloading config", e);
            Toast.makeText(requireContext(), "重载失败: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void applyEditedConfig(String editedJson) {
        try {
            // 验证 JSON 合法性
            new JSONObject(editedJson);

            ConfigManager config = getConfigManager();
            if (config == null) {
                Toast.makeText(requireContext(), "ConfigManager 未初始化", Toast.LENGTH_SHORT).show();
                return;
            }

            config.applyConfig(editedJson);
            refreshConfig();
            Toast.makeText(requireContext(), "配置已应用", Toast.LENGTH_SHORT).show();
            Log.i(TAG, "Config applied from editor");

        } catch (org.json.JSONException e) {
            Log.e(TAG, "Invalid JSON in editor", e);
            Toast.makeText(requireContext(), "JSON 格式错误: " + e.getMessage(), Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            Log.e(TAG, "Error applying config from editor", e);
            Toast.makeText(requireContext(), "应用失败: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    // ── 工具方法 ────────────────────────────────────────────

    private ConfigManager getConfigManager() {
        try {
            return ConfigManager.getInstance();
        } catch (IllegalStateException e) {
            Log.w(TAG, "ConfigManager not initialized", e);
            return null;
        }
    }

    private void setStatusText(String text, String color) {
        if (statusText != null) {
            statusText.setText(text);
            statusText.setTextColor(Color.parseColor(color));
            statusText.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        }
    }

    private void setText(TextView tv, String text, String color) {
        if (tv != null) {
            tv.setText(text);
            tv.setTextColor(Color.parseColor(color));
        }
    }
}