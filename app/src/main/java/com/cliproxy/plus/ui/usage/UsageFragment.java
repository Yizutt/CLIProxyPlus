package com.cliproxy.plus.ui.usage;

import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.cardview.widget.CardView;
import androidx.fragment.app.Fragment;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Locale;
import java.util.Random;

/**
 * UsageFragment - 用量统计 (纯 Java UI)
 * 显示摘要卡片 (总请求数、总 Token 数、成功率) 和
 * 按模型拆分的明细列表，支持刷新。
 * 使用 Material Design 3 深色主题配色。
 */
public class UsageFragment extends Fragment {

    private static final String TAG = "UsageFragment";

    // ── MD3 深色主题颜色 ──────────────────────────────────
    private static final String COLOR_BG          = "#121212";
    private static final String COLOR_CARD_BG     = "#2A2A3E";
    private static final String COLOR_PRIMARY     = "#7C3AED";
    private static final String COLOR_SECONDARY   = "#9D4EDD";
    private static final String COLOR_TEXT        = "#E2E8F0";
    private static final String COLOR_TEXT_MUTED  = "#94A3B8";
    private static final String COLOR_SUCCESS     = "#22C55E";
    private static final String COLOR_WARNING     = "#F59E0B";
    private static final String COLOR_ERROR       = "#EF4444";
    private static final String COLOR_DIVIDER     = "#3A3A50";
    private static final String COLOR_BUTTON_RIPPLE = "#8B5CF6";

    private LinearLayout summaryContainer;
    private LinearLayout modelListContainer;
    private TextView totalRequestsText;
    private TextView totalTokensText;
    private TextView successRateText;
    private Button refreshButton;

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
        scrollView.setBackgroundColor(Color.parseColor(COLOR_BG));

        LinearLayout root = new LinearLayout(requireContext());
        root.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        root.setOrientation(LinearLayout.VERTICAL);

        // 标题与副标题
        root.addView(createTitle("Usage Statistics"));
        root.addView(createSubtitle("Real-time API usage and token consumption"));

        // 刷新按钮
        refreshButton = createRefreshButton();
        root.addView(refreshButton);

        // 摘要卡片 — 三个统计项用水平行排列
        totalRequestsText = new TextView(requireContext());
        totalTokensText = new TextView(requireContext());
        successRateText = new TextView(requireContext());
        root.addView(createSummaryCard(
                totalRequestsText, totalTokensText, successRateText));

        // 摘要容器参考 (备用)
        summaryContainer = new LinearLayout(requireContext());
        summaryContainer.setOrientation(LinearLayout.VERTICAL);

        // 分隔标题
        root.addView(createSectionTitle("Per-Model Breakdown"));

        // 模型列表容器
        modelListContainer = new LinearLayout(requireContext());
        modelListContainer.setOrientation(LinearLayout.VERTICAL);
        root.addView(modelListContainer);

        scrollView.addView(root);
        return scrollView;
    }

    @Override
    public void onResume() {
        super.onResume();
        refreshData();
    }

    // ---------------------------------------------------------------
    // 数据刷新
    // ---------------------------------------------------------------

    private void refreshData() {
        Log.d(TAG, "Refreshing usage data...");
        loadSampleData();
    }

    /**
     * 用模拟数据填充 UI，后续可替换为从 ConfigManager / 统计文件读取。
     */
    private void loadSampleData() {
        Random rnd = new Random();

        int totalRequests = 150 + rnd.nextInt(200);
        int totalTokens   = 50000 + rnd.nextInt(200000);
        double successPct = 85.0 + rnd.nextDouble() * 14.0; // 85 ~ 99

        // 摘要卡片 — 设置文本和颜色
        setText(totalRequestsText,
                String.valueOf(totalRequests), COLOR_TEXT);
        setText(totalTokensText,
                String.format(Locale.US, "%,d", totalTokens), COLOR_TEXT);
        String rateColor = successPct >= 95.0 ? COLOR_SUCCESS
                : successPct >= 85.0 ? COLOR_WARNING : COLOR_ERROR;
        setText(successRateText,
                String.format(Locale.US, "%.1f%%", successPct), rateColor);

        // 构造模拟的模型数据
        String[] models = {"gpt-4o", "gpt-4o-mini", "claude-3-opus", "claude-3-sonnet",
                "gemini-2.0-flash", "deepseek-chat"};
        JSONArray modelArray = new JSONArray();
        for (String model : models) {
            try {
                JSONObject entry = new JSONObject();
                entry.put("model", model);
                entry.put("requests", 10 + rnd.nextInt(90));
                entry.put("tokens", 2000 + rnd.nextInt(50000));
                entry.put("success", 80 + rnd.nextInt(20));
                modelArray.put(entry);
            } catch (Exception e) {
                Log.e(TAG, "Error building sample model entry", e);
            }
        }

        renderModelList(modelArray);
    }

    /**
     * 渲染模型明细列表。接受 JSONArray，每项包含
     * model, requests, tokens, success 字段。
     */
    private void renderModelList(JSONArray models) {
        modelListContainer.removeAllViews();

        if (models == null || models.length() == 0) {
            TextView empty = new TextView(requireContext());
            empty.setText("No model data available.");
            empty.setTextColor(Color.parseColor(COLOR_TEXT_MUTED));
            empty.setTextSize(15);
            empty.setPadding(0, 16, 0, 8);
            modelListContainer.addView(empty);
            return;
        }

        for (int i = 0; i < models.length(); i++) {
            try {
                JSONObject entry = models.getJSONObject(i);
                String model    = entry.optString("model", "unknown");
                int requests    = entry.optInt("requests", 0);
                int tokens      = entry.optInt("tokens", 0);
                int success     = entry.optInt("success", 0);
                double rate     = requests > 0 ? (success * 100.0 / requests) : 0.0;

                modelListContainer.addView(createModelItem(model, requests, tokens, rate));
            } catch (Exception e) {
                Log.w(TAG, "Skipping invalid model entry at index " + i, e);
            }
        }
    }

    // ---------------------------------------------------------------
    // UI 构建辅助
    // ---------------------------------------------------------------

    private TextView createTitle(String text) {
        TextView tv = new TextView(requireContext());
        tv.setText(text);
        tv.setTextSize(26);
        tv.setTextColor(Color.parseColor(COLOR_TEXT));
        tv.setTypeface(null, Typeface.BOLD);
        tv.setPadding(0, 0, 0, 2);
        return tv;
    }

    private TextView createSubtitle(String text) {
        TextView tv = new TextView(requireContext());
        tv.setText(text);
        tv.setTextSize(14);
        tv.setTextColor(Color.parseColor(COLOR_TEXT_MUTED));
        tv.setPadding(0, 0, 0, 16);
        return tv;
    }

    private TextView createSectionTitle(String text) {
        TextView tv = new TextView(requireContext());
        tv.setText(text);
        tv.setTextSize(18);
        tv.setTextColor(Color.parseColor(COLOR_TEXT));
        tv.setTypeface(null, Typeface.BOLD);
        tv.setPadding(0, 20, 0, 12);
        return tv;
    }

    private Button createRefreshButton() {
        Button btn = new Button(requireContext());
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, 0, 0, 16);
        btn.setLayoutParams(lp);
        btn.setText("⟳ Refresh Data");
        btn.setTextColor(Color.parseColor("#FFFFFF"));
        btn.setTextSize(14);
        btn.setAllCaps(false);
        btn.setPadding(28, 10, 28, 10);
        btn.setElevation(2);

        // 圆角背景
        GradientDrawable drawable = new GradientDrawable();
        drawable.setShape(GradientDrawable.RECTANGLE);
        drawable.setCornerRadius(24);
        drawable.setColor(Color.parseColor(COLOR_PRIMARY));
        btn.setBackground(drawable);

        btn.setOnClickListener(v -> refreshData());
        return btn;
    }

    /**
     * 创建摘要卡片 — 三个统计项以水平行排列，每项带标签。
     */
    private CardView createSummaryCard(TextView... values) {
        CardView card = new CardView(requireContext());
        LinearLayout.LayoutParams cardParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        cardParams.setMargins(0, 0, 0, 4);
        card.setLayoutParams(cardParams);
        card.setCardBackgroundColor(Color.parseColor(COLOR_CARD_BG));
        card.setRadius(16);
        card.setCardElevation(0);
        card.setUseCompatPadding(true);

        LinearLayout content = new LinearLayout(requireContext());
        content.setOrientation(LinearLayout.HORIZONTAL);
        content.setPadding(8, 16, 8, 16);

        // 标签和值对
        String[] labels = {"Requests", "Tokens", "Success"};

        for (int i = 0; i < 3; i++) {
            LinearLayout item = new LinearLayout(requireContext());
            item.setOrientation(LinearLayout.VERTICAL);
            item.setGravity(Gravity.CENTER_HORIZONTAL);
            LinearLayout.LayoutParams itemLp = new LinearLayout.LayoutParams(
                    0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f);
            item.setLayoutParams(itemLp);
            item.setPadding(8, 0, 8, 0);

            // 标签
            TextView label = new TextView(requireContext());
            label.setText(labels[i]);
            label.setTextSize(12);
            label.setTextColor(Color.parseColor(COLOR_TEXT_MUTED));
            label.setGravity(Gravity.CENTER_HORIZONTAL);
            label.setPadding(0, 0, 0, 4);
            item.addView(label);

            // 值
            TextView value = values[i];
            if (value.getParent() != null) {
                ((ViewGroup) value.getParent()).removeView(value);
            }
            value.setTextSize(22);
            value.setTypeface(null, Typeface.BOLD);
            value.setGravity(Gravity.CENTER_HORIZONTAL);
            // 避免值被 padding 截断
            value.setPadding(0, 0, 0, 0);
            item.addView(value);

            // 分隔竖线 (非最后一项)
            if (i < 2) {
                View divider = new View(requireContext());
                LinearLayout.LayoutParams divLp = new LinearLayout.LayoutParams(
                        1, ViewGroup.LayoutParams.MATCH_PARENT);
                divLp.setMargins(0, 8, 0, 8);
                divider.setLayoutParams(divLp);
                divider.setBackgroundColor(Color.parseColor(COLOR_DIVIDER));
                content.addView(item);
                content.addView(divider);
            } else {
                content.addView(item);
            }
        }

        card.addView(content);
        return card;
    }

    /**
     * 创建单个模型的行卡片，包含模型名、请求数、Token 数、成功率。
     */
    private CardView createModelItem(String modelName, int requests, int tokens, double successRate) {
        CardView card = new CardView(requireContext());
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, 0, 0, 10);
        card.setLayoutParams(lp);
        card.setCardBackgroundColor(Color.parseColor(COLOR_CARD_BG));
        card.setRadius(14);
        card.setCardElevation(0);
        card.setUseCompatPadding(true);

        LinearLayout content = new LinearLayout(requireContext());
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(16, 14, 16, 14);

        // ── 第一行：模型名称 + 状态圆点 ──
        LinearLayout headerRow = new LinearLayout(requireContext());
        headerRow.setOrientation(LinearLayout.HORIZONTAL);
        headerRow.setGravity(Gravity.CENTER_VERTICAL);

        // 状态圆点
        View dot = new View(requireContext());
        int dotSize = 10;
        LinearLayout.LayoutParams dotLp = new LinearLayout.LayoutParams(dotSize, dotSize);
        dotLp.setMargins(0, 0, 8, 0);
        dot.setLayoutParams(dotLp);
        String dotColor = successRate >= 95.0 ? COLOR_SUCCESS
                : successRate >= 85.0 ? COLOR_WARNING : COLOR_ERROR;
        GradientDrawable dotDrawable = new GradientDrawable();
        dotDrawable.setShape(GradientDrawable.OVAL);
        dotDrawable.setColor(Color.parseColor(dotColor));
        dot.setBackground(dotDrawable);
        headerRow.addView(dot);

        // 模型名称
        TextView nameView = new TextView(requireContext());
        nameView.setText(modelName);
        nameView.setTextSize(15);
        nameView.setTextColor(Color.parseColor(COLOR_TEXT));
        nameView.setTypeface(null, Typeface.BOLD);
        nameView.setPadding(0, 0, 0, 0);
        headerRow.addView(nameView, new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f));

        // 成功率标签
        TextView rateLabel = new TextView(requireContext());
        rateLabel.setText(String.format(Locale.US, "%.1f%%", successRate));
        rateLabel.setTextSize(14);
        rateLabel.setTypeface(null, Typeface.BOLD);
        String rateColor = successRate >= 95.0 ? COLOR_SUCCESS
                : successRate >= 85.0 ? COLOR_WARNING : COLOR_ERROR;
        rateLabel.setTextColor(Color.parseColor(rateColor));
        headerRow.addView(rateLabel);

        content.addView(headerRow);

        // ── 分隔线 ──
        View divider = new View(requireContext());
        LinearLayout.LayoutParams divParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 1);
        divParams.setMargins(0, 10, 0, 10);
        divider.setLayoutParams(divParams);
        divider.setBackgroundColor(Color.parseColor(COLOR_DIVIDER));
        content.addView(divider);

        // ── 第二行：指标图标行 ──
        LinearLayout metricsRow = new LinearLayout(requireContext());
        metricsRow.setOrientation(LinearLayout.HORIZONTAL);

        // 请求数
        LinearLayout reqBlock = buildMetricBlock("Requests", String.valueOf(requests));
        metricsRow.addView(reqBlock);

        // Token 数
        LinearLayout tokBlock = buildMetricBlock("Tokens",
                String.format(Locale.US, "%,d", tokens));
        metricsRow.addView(tokBlock);

        content.addView(metricsRow);
        card.addView(content);
        return card;
    }

    /**
     * 构建单个指标块 (迷你标签 + 值)。
     */
    private LinearLayout buildMetricBlock(String label, String value) {
        LinearLayout block = new LinearLayout(requireContext());
        block.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams blockLp = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f);
        block.setLayoutParams(blockLp);

        TextView labelView = new TextView(requireContext());
        labelView.setText(label);
        labelView.setTextSize(11);
        labelView.setTextColor(Color.parseColor(COLOR_TEXT_MUTED));
        labelView.setPadding(0, 0, 0, 2);
        block.addView(labelView);

        TextView valueView = new TextView(requireContext());
        valueView.setText(value);
        valueView.setTextSize(14);
        valueView.setTextColor(Color.parseColor(COLOR_TEXT));
        block.addView(valueView);

        return block;
    }

    private void setText(TextView tv, String text, String color) {
        if (tv != null) {
            tv.setText(text);
            tv.setTextColor(Color.parseColor(color));
        }
    }
}