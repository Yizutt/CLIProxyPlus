package com.cliproxy.plus.ui.usage;

import android.graphics.Color;
import android.graphics.Typeface;
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
 */
public class UsageFragment extends Fragment {

    private static final String TAG = "UsageFragment";

    // 颜色常量
    private static final String COLOR_BG          = "#1E1E2E";
    private static final String COLOR_CARD_BG     = "#313244";
    private static final String COLOR_TEXT        = "#CDD6F4";
    private static final String COLOR_TEXT_MUTED  = "#A6ADC8";
    private static final String COLOR_TITLE       = "#F5C2E7";
    private static final String COLOR_PRIMARY     = "#7C3AED";
    private static final String COLOR_SUCCESS     = "#22C55E";
    private static final String COLOR_WARNING     = "#F59E0B";
    private static final String COLOR_ERROR       = "#EF4444";

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

        // 标题
        root.addView(createTitle("Usage Statistics"));

        // 刷新按钮
        refreshButton = createRefreshButton();
        root.addView(refreshButton);

        // 摘要卡片
        totalRequestsText = new TextView(requireContext());
        totalTokensText = new TextView(requireContext());
        successRateText = new TextView(requireContext());
        root.addView(createCard("Summary",
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
        // 模拟数据 — 替换为真实数据源
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

        // 摘要卡片
        setText(totalRequestsText,
                "Total Requests: " + totalRequests, COLOR_TEXT);
        setText(totalTokensText,
                "Total Tokens: " + String.format(Locale.US, "%,d", totalTokens), COLOR_TEXT);
        String rateColor = successPct >= 95.0 ? COLOR_SUCCESS
                : successPct >= 85.0 ? COLOR_WARNING : COLOR_ERROR;
        setText(successRateText,
                "Success Rate: " + String.format(Locale.US, "%.1f%%", successPct),
                rateColor);

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
            empty.setPadding(0, 8, 0, 8);
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
        tv.setTextSize(24);
        tv.setTextColor(Color.parseColor(COLOR_TITLE));
        tv.setTypeface(null, Typeface.BOLD);
        tv.setPadding(0, 0, 0, 12);
        return tv;
    }

    private TextView createSectionTitle(String text) {
        TextView tv = new TextView(requireContext());
        tv.setText(text);
        tv.setTextSize(18);
        tv.setTextColor(Color.parseColor(COLOR_PRIMARY));
        tv.setTypeface(null, Typeface.BOLD);
        tv.setPadding(0, 16, 0, 8);
        return tv;
    }

    private Button createRefreshButton() {
        Button btn = new Button(requireContext());
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, 0, 0, 12);
        btn.setLayoutParams(lp);
        btn.setText("Refresh");
        btn.setTextColor(Color.parseColor("#FFFFFF"));
        btn.setBackgroundColor(Color.parseColor(COLOR_PRIMARY));
        btn.setPadding(24, 8, 24, 8);
        btn.setOnClickListener(v -> refreshData());
        return btn;
    }

    private CardView createCard(String title, TextView... lines) {
        CardView card = new CardView(requireContext());
        card.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        card.setCardBackgroundColor(Color.parseColor(COLOR_CARD_BG));
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
        titleView.setTextColor(Color.parseColor(COLOR_PRIMARY));
        titleView.setTypeface(null, Typeface.BOLD);
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

    /**
     * 创建单个模型的行卡片，包含模型名、请求数、Token 数、成功率。
     */
    private CardView createModelItem(String modelName, int requests, int tokens, double successRate) {
        CardView card = new CardView(requireContext());
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, 0, 0, 8);
        card.setLayoutParams(lp);
        card.setCardBackgroundColor(Color.parseColor(COLOR_CARD_BG));
        card.setRadius(10);
        card.setCardElevation(2);
        card.setUseCompatPadding(true);

        LinearLayout content = new LinearLayout(requireContext());
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(14, 12, 14, 12);

        // 模型名称
        TextView nameView = new TextView(requireContext());
        nameView.setText(modelName);
        nameView.setTextSize(16);
        nameView.setTextColor(Color.parseColor(COLOR_TITLE));
        nameView.setTypeface(null, Typeface.BOLD);
        nameView.setPadding(0, 0, 0, 6);
        content.addView(nameView);

        // 指标行
        LinearLayout metricsRow = new LinearLayout(requireContext());
        metricsRow.setOrientation(LinearLayout.HORIZONTAL);

        // 请求数
        TextView reqView = new TextView(requireContext());
        reqView.setText("Requests: " + requests);
        reqView.setTextSize(14);
        reqView.setTextColor(Color.parseColor(COLOR_TEXT));
        reqView.setPadding(0, 0, 24, 0);
        metricsRow.addView(reqView);

        // Token 数
        TextView tokView = new TextView(requireContext());
        tokView.setText("Tokens: " + String.format(Locale.US, "%,d", tokens));
        tokView.setTextSize(14);
        tokView.setTextColor(Color.parseColor(COLOR_TEXT));
        tokView.setPadding(0, 0, 24, 0);
        metricsRow.addView(tokView);

        // 成功率
        TextView rateView = new TextView(requireContext());
        rateView.setText("Rate: " + String.format(Locale.US, "%.1f%%", successRate));
        rateView.setTextSize(14);
        String rateColor = successRate >= 95.0 ? COLOR_SUCCESS
                : successRate >= 85.0 ? COLOR_WARNING : COLOR_ERROR;
        rateView.setTextColor(Color.parseColor(rateColor));
        metricsRow.addView(rateView);

        content.addView(metricsRow);
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