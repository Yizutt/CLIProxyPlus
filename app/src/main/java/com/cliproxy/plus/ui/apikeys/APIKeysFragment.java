package com.cliproxy.plus.ui.apikeys;

import android.content.ClipData;
import android.content.ClipboardManager;
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

import com.cliproxy.plus.auth.AuthManager;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * APIKeysFragment - API Key 管理
 * 管理 Claude/Codex/Gemini/xAI/Vertex/OpenAI-Compat 的 API Key
 * 纯 Java UI，卡片式布局，按提供商分组。支持添加、复制、删除密钥。
 */
public class APIKeysFragment extends Fragment {

    private static final String TAG = "APIKeysFragment";

    private static final String[] PROVIDERS = {
            "Claude", "Codex", "Gemini", "xAI", "Vertex", "OpenAI-Compat"
    };

    private static final String[] PROVIDER_ICONS = {
            "\uD83E\uDD16", "\uD83D\uDCDD", "\uD83D\uDC8E", "\uD83D\uDD25", "\u2601\uFE0F", "\uD83D\uDD17"
    };

    private LinearLayout root;
    private final Map<String, List<AuthManager.AuthCredential>> keyStore = new LinkedHashMap<>();

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
        root.addView(createTitle("API Keys"));

        // 操作按钮栏
        root.addView(createActionBar());

        // 从 AuthManager 加载已有密钥
        loadKeysFromAuthManager();

        // 确保每个提供商都有条目
        for (String provider : PROVIDERS) {
            if (!keyStore.containsKey(provider)) {
                keyStore.put(provider, new ArrayList<AuthManager.AuthCredential>());
            }
        }

        // 为每个提供商创建卡片区域
        for (int i = 0; i < PROVIDERS.length; i++) {
            String provider = PROVIDERS[i];
            List<AuthManager.AuthCredential> keys = keyStore.get(provider);
            root.addView(createProviderCard(i, provider, keys));
        }

        scrollView.addView(root);
        return scrollView;
    }

    @Override
    public void onResume() {
        super.onResume();
        refreshAllCards();
    }

    // ── 标题 ────────────────────────────────────────────────

    private TextView createTitle(String text) {
        TextView tv = new TextView(requireContext());
        tv.setText(text);
        tv.setTextSize(24);
        tv.setTextColor(Color.parseColor("#F5C2E7"));
        tv.setTypeface(null, android.graphics.Typeface.BOLD);
        tv.setPadding(0, 0, 0, 16);
        return tv;
    }

    // ── 操作栏 ──────────────────────────────────────────────

    private LinearLayout createActionBar() {
        LinearLayout bar = new LinearLayout(requireContext());
        bar.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setPadding(0, 0, 0, 16);

        // 添加按钮
        Button addButton = new Button(requireContext());
        LinearLayout.LayoutParams addParams = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f);
        addParams.setMargins(0, 0, 8, 0);
        addButton.setLayoutParams(addParams);
        addButton.setText("+ 添加 API Key");
        addButton.setTextColor(Color.parseColor("#FFFFFF"));
        addButton.setBackgroundColor(Color.parseColor("#7C3AED"));
        addButton.setPadding(12, 10, 12, 10);
        addButton.setAllCaps(false);
        addButton.setTextSize(14);
        addButton.setOnClickListener(v -> showAddKeyDialog());

        // 刷新按钮
        Button refreshButton = new Button(requireContext());
        LinearLayout.LayoutParams refreshParams = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f);
        refreshParams.setMargins(8, 0, 0, 0);
        refreshButton.setLayoutParams(refreshParams);
        refreshButton.setText("\u27F3 刷新");
        refreshButton.setTextColor(Color.parseColor("#CDD6F4"));
        refreshButton.setBackgroundColor(Color.parseColor("#45475A"));
        refreshButton.setPadding(12, 10, 12, 10);
        refreshButton.setAllCaps(false);
        refreshButton.setTextSize(14);
        refreshButton.setOnClickListener(v -> refreshAllCards());

        bar.addView(addButton);
        bar.addView(refreshButton);

        return bar;
    }

    // ── 提供商卡片 ──────────────────────────────────────────

    private CardView createProviderCard(int index, String provider,
                                         List<AuthManager.AuthCredential> keys) {
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

        // ── 提供商标题行 ──
        LinearLayout headerRow = new LinearLayout(requireContext());
        headerRow.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        headerRow.setOrientation(LinearLayout.HORIZONTAL);
        headerRow.setGravity(Gravity.CENTER_VERTICAL);

        TextView iconView = new TextView(requireContext());
        iconView.setText(PROVIDER_ICONS[index]);
        iconView.setTextSize(20);
        iconView.setPadding(0, 0, 8, 0);
        headerRow.addView(iconView);

        TextView titleView = new TextView(requireContext());
        titleView.setText(provider);
        titleView.setTextSize(18);
        titleView.setTextColor(Color.parseColor("#7C3AED"));
        titleView.setTypeface(null, android.graphics.Typeface.BOLD);
        titleView.setLayoutParams(new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f));
        headerRow.addView(titleView);

        // 密钥数量标签
        TextView countBadge = new TextView(requireContext());
        countBadge.setText(keys.size() + " 个密钥");
        countBadge.setTextSize(12);
        countBadge.setTextColor(Color.parseColor("#A6ADC8"));
        countBadge.setPadding(8, 4, 8, 4);
        countBadge.setBackgroundColor(Color.parseColor("#45475A"));
        countBadge.setGravity(Gravity.CENTER);
        headerRow.addView(countBadge);

        content.addView(headerRow);

        // ── 分隔线 ──
        View divider = new View(requireContext());
        LinearLayout.LayoutParams divParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 1);
        divParams.setMargins(0, 10, 0, 10);
        divider.setLayoutParams(divParams);
        divider.setBackgroundColor(Color.parseColor("#45475A"));
        content.addView(divider);

        // ── 密钥列表 ──
        if (keys.isEmpty()) {
            TextView emptyView = new TextView(requireContext());
            emptyView.setText("暂无密钥，点击上方 \"+ 添加\" 添加");
            emptyView.setTextSize(14);
            emptyView.setTextColor(Color.parseColor("#6C7086"));
            emptyView.setPadding(0, 8, 0, 8);
            emptyView.setGravity(Gravity.CENTER);
            content.addView(emptyView);
        } else {
            for (int i = 0; i < keys.size(); i++) {
                AuthManager.AuthCredential cred = keys.get(i);
                content.addView(createKeyRow(provider, cred, i == keys.size() - 1));
            }
        }

        card.addView(content);
        return card;
    }

    // ── 单行密钥 ────────────────────────────────────────────

    private View createKeyRow(String provider, AuthManager.AuthCredential cred,
                               boolean isLast) {
        LinearLayout row = new LinearLayout(requireContext());
        LinearLayout.LayoutParams rowParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        if (!isLast) {
            rowParams.setMargins(0, 0, 0, 8);
        }
        row.setLayoutParams(rowParams);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(8, 8, 8, 8);
        row.setBackgroundColor(Color.parseColor("#1E1E2E"));
        row.setMinimumHeight(48);

        // 状态指示点
        String statusColor = cred.isAvailable() ? "#22C55E" : "#F38BA8";
        View statusDot = new View(requireContext());
        LinearLayout.LayoutParams dotParams = new LinearLayout.LayoutParams(8, 8);
        dotParams.setMargins(0, 0, 8, 0);
        statusDot.setLayoutParams(dotParams);
        statusDot.setBackgroundColor(Color.parseColor(statusColor));
        row.addView(statusDot);

        // 标签
        String label = (cred.label != null && !cred.label.isEmpty())
                ? cred.label : cred.id;
        TextView labelView = new TextView(requireContext());
        labelView.setText(label);
        labelView.setTextSize(14);
        labelView.setTextColor(Color.parseColor("#CDD6F4"));
        labelView.setTypeface(null, android.graphics.Typeface.BOLD);
        labelView.setPadding(0, 0, 8, 0);
        row.addView(labelView);

        // 密钥类型标签
        TextView typeView = new TextView(requireContext());
        typeView.setText(cred.type == AuthManager.AuthCredential.AuthType.API_KEY
                ? "API" : "OAuth");
        typeView.setTextSize(11);
        typeView.setTextColor(Color.parseColor("#A6ADC8"));
        typeView.setPadding(4, 2, 4, 2);
        typeView.setBackgroundColor(Color.parseColor("#45475A"));
        typeView.setGravity(Gravity.CENTER);
        typeView.setPadding(0, 0, 8, 0);
        row.addView(typeView);

        // 密钥 ID（掩码显示）
        String keyId = cred.id;
        TextView keyView = new TextView(requireContext());
        keyView.setText(maskKey(keyId));
        keyView.setTextSize(13);
        keyView.setTextColor(Color.parseColor("#6C7086"));
        keyView.setLayoutParams(new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f));
        keyView.setPadding(0, 0, 8, 0);
        row.addView(keyView);

        // 复制按钮
        Button copyBtn = new Button(requireContext());
        copyBtn.setText("复制");
        copyBtn.setTextSize(11);
        copyBtn.setTextColor(Color.parseColor("#7C3AED"));
        copyBtn.setBackgroundColor(Color.parseColor("#313244"));
        copyBtn.setPadding(8, 4, 8, 4);
        copyBtn.setAllCaps(false);
        final String credentialId = cred.id;
        copyBtn.setOnClickListener(v -> {
            ClipboardManager clipboard =
                    (ClipboardManager) requireContext()
                            .getSystemService(requireContext().CLIPBOARD_SERVICE);
            ClipData clip = ClipData.newPlainText("Credential ID", credentialId);
            clipboard.setPrimaryClip(clip);
            Toast.makeText(requireContext(), "已复制凭证 ID: " + credentialId,
                    Toast.LENGTH_SHORT).show();
        });
        row.addView(copyBtn);

        // 删除按钮
        Button deleteBtn = new Button(requireContext());
        deleteBtn.setText("\u2715");
        deleteBtn.setTextSize(13);
        deleteBtn.setTextColor(Color.parseColor("#F38BA8"));
        deleteBtn.setBackgroundColor(Color.parseColor("#313244"));
        deleteBtn.setPadding(8, 4, 8, 4);
        deleteBtn.setAllCaps(false);
        deleteBtn.setOnClickListener(v -> {
            removeKey(provider, cred);
            Toast.makeText(requireContext(), "已删除 " + label, Toast.LENGTH_SHORT).show();
        });
        row.addView(deleteBtn);

        return row;
    }

    // ── 添加密钥对话框 ──────────────────────────────────────

    private void showAddKeyDialog() {
        android.app.AlertDialog.Builder builder =
                new android.app.AlertDialog.Builder(requireContext());
        builder.setTitle("添加 API Key");

        LinearLayout dialogLayout = new LinearLayout(requireContext());
        dialogLayout.setOrientation(LinearLayout.VERTICAL);
        dialogLayout.setPadding(24, 16, 24, 16);

        // 提供商选择提示
        TextView providerLabel = new TextView(requireContext());
        providerLabel.setText("选择提供商:");
        providerLabel.setTextSize(14);
        providerLabel.setTextColor(Color.parseColor("#CDD6F4"));
        providerLabel.setPadding(0, 0, 0, 8);
        dialogLayout.addView(providerLabel);

        // 提供商选择按钮组
        final String[] selectedProvider = {PROVIDERS[0]};
        LinearLayout providerChips = new LinearLayout(requireContext());
        providerChips.setOrientation(LinearLayout.HORIZONTAL);
        providerChips.setPadding(0, 0, 0, 16);

        for (int i = 0; i < PROVIDERS.length; i++) {
            final int idx = i;
            Button chip = new Button(requireContext());
            LinearLayout.LayoutParams chipParams = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT);
            chipParams.setMargins(0, 0, 6, 0);
            chip.setLayoutParams(chipParams);
            chip.setText(PROVIDERS[i]);
            chip.setTextSize(12);
            chip.setTextColor(Color.parseColor("#FFFFFF"));
            chip.setPadding(10, 6, 10, 6);
            chip.setAllCaps(false);
            chip.setOnClickListener(v -> {
                selectedProvider[0] = PROVIDERS[idx];
                for (int j = 0; j < providerChips.getChildCount(); j++) {
                    Button b = (Button) providerChips.getChildAt(j);
                    b.setBackgroundColor(Color.parseColor("#45475A"));
                }
                chip.setBackgroundColor(Color.parseColor("#7C3AED"));
            });
            // 默认选中第一个
            chip.setBackgroundColor(i == 0
                    ? Color.parseColor("#7C3AED")
                    : Color.parseColor("#45475A"));
            providerChips.addView(chip);
        }
        dialogLayout.addView(providerChips);

        // 标签输入
        EditText labelInput = new EditText(requireContext());
        labelInput.setHint("标签 (如: 工作用, 主密钥)");
        labelInput.setTextColor(Color.parseColor("#CDD6F4"));
        labelInput.setHintTextColor(Color.parseColor("#6C7086"));
        labelInput.setBackgroundColor(Color.parseColor("#313244"));
        labelInput.setPadding(12, 10, 12, 10);
        labelInput.setTextSize(14);
        LinearLayout.LayoutParams labelInputParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        labelInputParams.setMargins(0, 0, 0, 12);
        labelInput.setLayoutParams(labelInputParams);
        dialogLayout.addView(labelInput);

        // 密钥输入
        EditText keyInput = new EditText(requireContext());
        keyInput.setHint("API Key");
        keyInput.setTextColor(Color.parseColor("#CDD6F4"));
        keyInput.setHintTextColor(Color.parseColor("#6C7086"));
        keyInput.setBackgroundColor(Color.parseColor("#313244"));
        keyInput.setPadding(12, 10, 12, 10);
        keyInput.setTextSize(14);
        dialogLayout.addView(keyInput);

        builder.setView(dialogLayout);

        builder.setPositiveButton("添加", (dialog, which) -> {
            String provider = selectedProvider[0];
            String key = keyInput.getText().toString().trim();
            String label = labelInput.getText().toString().trim();
            if (key.isEmpty()) {
                Toast.makeText(requireContext(), "API Key 不能为空",
                        Toast.LENGTH_SHORT).show();
                return;
            }
            if (label.isEmpty()) {
                label = provider + " Key";
            }
            addKey(provider, key, label);
        });

        builder.setNegativeButton("取消", null);
        builder.show();
    }

    // ── 数据操作 ────────────────────────────────────────────

    private void loadKeysFromAuthManager() {
        AuthManager authManager = AuthManager.getInstance();

        // 初始化所有提供商的列表
        for (String provider : PROVIDERS) {
            keyStore.put(provider, new ArrayList<AuthManager.AuthCredential>());
        }

        // 从 AuthManager 获取所有凭证并按提供商分组
        List<AuthManager.AuthCredential> allCredentials = authManager.listCredentials();
        Log.d(TAG, "Loaded " + allCredentials.size() + " credentials from AuthManager");

        for (AuthManager.AuthCredential cred : allCredentials) {
            String mappedProvider = mapProviderName(cred.provider);
            List<AuthManager.AuthCredential> keys = keyStore.get(mappedProvider);
            if (keys != null) {
                keys.add(cred);
            } else {
                // 未匹配到已知提供商，添加到第一个匹配的或 OpenAI-Compat
                Log.d(TAG, "Unmapped provider: " + cred.provider
                        + ", adding to OpenAI-Compat");
                keyStore.get("OpenAI-Compat").add(cred);
            }
        }
    }

    private String mapProviderName(String authProvider) {
        if (authProvider == null) return "OpenAI-Compat";
        String lower = authProvider.toLowerCase();
        if (lower.contains("claude") || lower.contains("anthropic")) return "Claude";
        if (lower.contains("codex")) return "Codex";
        if (lower.contains("gemini")) return "Gemini";
        if (lower.contains("xai") || lower.contains("grok")) return "xAI";
        if (lower.contains("vertex")) return "Vertex";
        // 默认映射到 OpenAI-Compat
        return "OpenAI-Compat";
    }

    private String mapProviderToAuthName(String uiProvider) {
        if (uiProvider == null) return "openai-compat";
        String lower = uiProvider.toLowerCase();
        if (lower.contains("claude")) return "claude";
        if (lower.contains("codex")) return "codex";
        if (lower.contains("gemini")) return "gemini";
        if (lower.contains("xai")) return "xai";
        if (lower.contains("vertex")) return "vertex";
        return "openai-compat";
    }

    private void addKey(String provider, String key, String label) {
        AuthManager authManager = AuthManager.getInstance();

        String id = label + "_" + System.currentTimeMillis();
        String authProvider = mapProviderToAuthName(provider);

        AuthManager.AuthCredential credential = new AuthManager.AuthCredential();
        credential.id = id;
        credential.provider = authProvider;
        credential.label = label;
        credential.type = AuthManager.AuthCredential.AuthType.API_KEY;
        credential.metadata.put("key", key);

        authManager.registerCredential(credential);
        Log.d(TAG, "Registered credential: " + id + " under provider " + authProvider);

        // 刷新 UI
        refreshAllCards();
        Toast.makeText(requireContext(),
                "已添加 " + label + " 到 " + provider, Toast.LENGTH_SHORT).show();
    }

    private void removeKey(String provider, AuthManager.AuthCredential cred) {
        AuthManager authManager = AuthManager.getInstance();
        authManager.removeCredential(cred.id);
        Log.d(TAG, "Removed credential: " + cred.id);

        List<AuthManager.AuthCredential> keys = keyStore.get(provider);
        if (keys != null) {
            keys.remove(cred);
        }

        // 刷新 UI
        refreshAllCards();
    }

    // ── UI 刷新 ─────────────────────────────────────────────

    private void refreshAllCards() {
        if (!isAdded()) return;

        // 重新加载数据
        keyStore.clear();
        loadKeysFromAuthManager();

        // 确保每个提供商都有条目
        for (String provider : PROVIDERS) {
            if (!keyStore.containsKey(provider)) {
                keyStore.put(provider, new ArrayList<AuthManager.AuthCredential>());
            }
        }

        // 移除所有现有的卡片（保留标题和操作栏）
        while (root.getChildCount() > 2) {
            root.removeViewAt(root.getChildCount() - 1);
        }

        // 重新创建每个提供商的卡片
        for (int i = 0; i < PROVIDERS.length; i++) {
            String provider = PROVIDERS[i];
            List<AuthManager.AuthCredential> keys = keyStore.get(provider);
            root.addView(createProviderCard(i, provider, keys));
        }
    }

    // ── 工具方法 ────────────────────────────────────────────

    private String maskKey(String key) {
        if (key == null) return "";
        int len = key.length();
        if (len <= 8) return key.substring(0, Math.min(4, len)) + "****";
        return key.substring(0, 4) + "..." + key.substring(len - 4);
    }
}