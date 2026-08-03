package com.cliproxy.plus.ui.auth;

import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.cardview.widget.CardView;
import androidx.fragment.app.Fragment;

import com.cliproxy.plus.auth.AuthManager;

/**
 * Auth Files - 账号管理
 */
public class AuthFragment extends Fragment {

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

        LinearLayout root = new LinearLayout(requireContext());
        root.setOrientation(LinearLayout.VERTICAL);
        root.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));

        // 标题
        root.addView(makeTitle("Auth Files"));

        // 账号统计
        AuthManager am = AuthManager.getInstance();
        root.addView(makeCard("凭证概览",
            makeInfoRow("总凭证数", String.valueOf(am.getTotalCount())),
            makeInfoRow("活跃凭证", String.valueOf(am.getActiveCount())),
            makeInfoRow("路由策略", am.getStrategy().toString())));

        // 提供商列表
        root.addView(makeCard("支持的提供商",
            makeInfoRow("OAuth", "Claude, Codex, Gemini, Antigravity, Kimi, xAI, Kiro, Copilot, Kilo, GitLab, CodeBuddy, Cursor, Qoder, iFlow"),
            makeInfoRow("API Key", "Claude, Codex, Gemini, xAI, Vertex, OpenAI-Compat"),
            makeInfoRow("其他", "Kiro, Kilo (Token Import)")));

        // 使用说明
        root.addView(makeCard("使用说明",
            makeInfoRow("\u25B6 OAuth", "在 OAuth 标签页发起登录"),
            makeInfoRow("\u25B6 API Key", "在 API Keys 标签页添加密钥"),
            makeInfoRow("\u25B6 管理", "在 Config 标签页查看配置")));

        scroll.addView(root);
        return scroll;
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