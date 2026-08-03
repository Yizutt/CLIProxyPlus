package com.cliproxy.plus.ui.dashboard;

import android.graphics.Color;
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
import com.cliproxy.plus.config.ConfigManager;

/**
 * DashboardFragment - 仪表盘 (纯 Java UI)
 */
public class DashboardFragment extends Fragment {

    private TextView serverStatusText;
    private TextView portText;
    private TextView requestCountText;
    private TextView activeAuthsText;
    private TextView totalTokensText;
    private TextView providersText;

    @Nullable
    @Override
    public ViewGroup onCreateView(@NonNull android.view.LayoutInflater inflater,
                                   @Nullable ViewGroup container,
                                   @Nullable Bundle savedInstanceState) {
        ScrollView scrollView = new ScrollView(requireContext());
        scrollView.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
        scrollView.setPadding(16, 16, 16, 16);
        scrollView.setBackgroundColor(Color.parseColor("#1E1E2E"));

        LinearLayout root = new LinearLayout(requireContext());
        root.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        root.setOrientation(LinearLayout.VERTICAL);

        // 标题
        root.addView(createTitle("Dashboard"));

        // 服务器状态卡片
        serverStatusText = new TextView(requireContext());
        portText = new TextView(requireContext());
        root.addView(createCard("服务器状态",
                serverStatusText, portText));

        // 统计卡片
        requestCountText = new TextView(requireContext());
        activeAuthsText = new TextView(requireContext());
        totalTokensText = new TextView(requireContext());
        root.addView(createCard("统计概览",
                requestCountText, activeAuthsText, totalTokensText));

        // 提供商卡片
        providersText = new TextView(requireContext());
        root.addView(createCard("已配置提供商", providersText));

        scrollView.addView(root);
        return scrollView;
    }

    @Override
    public void onResume() {
        super.onResume();
        refreshData();
    }

    private void refreshData() {
        ConfigManager config = ConfigManager.getInstance();
        AuthManager authManager = AuthManager.getInstance();

        setText(serverStatusText, "服务器状态: 运行中", "#22C55E");
        setText(portText, "端口: " + config.getInt("port", 8317), "#A6ADC8");
        setText(requestCountText, "今日请求: 0", "#CDD6F4");
        setText(activeAuthsText, "活跃账号: " + authManager.getActiveCount(), "#CDD6F4");
        setText(totalTokensText, "总 Token 消耗: 0", "#CDD6F4");
        int total = authManager.getTotalCount();
        setText(providersText, total > 0 ? "已配置 " + total + " 个凭证" : "暂无配置", "#A6ADC8");
    }

    private TextView createTitle(String text) {
        TextView tv = new TextView(requireContext());
        tv.setText(text);
        tv.setTextSize(24);
        tv.setTextColor(Color.parseColor("#F5C2E7"));
        tv.setTypeface(null, android.graphics.Typeface.BOLD);
        tv.setPadding(0, 0, 0, 16);
        return tv;
    }

    private CardView createCard(String title, TextView... lines) {
        CardView card = new CardView(requireContext());
        card.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        card.setCardBackgroundColor(Color.parseColor("#313244"));
        card.setRadius(12);
        card.setCardElevation(4);
        card.setUseCompatPadding(true);

        LinearLayout.LayoutParams marginParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        marginParams.setMargins(0, 0, 0, 12);
        card.setLayoutParams(marginParams);

        LinearLayout content = new LinearLayout(requireContext());
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(16, 16, 16, 16);

        TextView titleView = new TextView(requireContext());
        titleView.setText(title);
        titleView.setTextSize(18);
        titleView.setTextColor(Color.parseColor("#3B82F6"));
        titleView.setTypeface(null, android.graphics.Typeface.BOLD);
        titleView.setPadding(0, 0, 0, 8);
        content.addView(titleView);

        for (TextView line : lines) {
            line.setTextSize(16);
            line.setPadding(0, 2, 0, 2);
            content.addView(line);
        }

        card.addView(content);
        return card;
    }

    private void setText(TextView tv, String text, String color) {
        if (tv != null) {
            tv.setText(text);
            tv.setTextColor(Color.parseColor(color));
        }
    }
}