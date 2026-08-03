package com.cliproxy.plus.ui.dashboard;

import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
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
 * Material Design 3 dark theme with modern card layouts.
 */
public class DashboardFragment extends Fragment {

    // ── MD3 Dark Theme Colors ──────────────────────────────────────
    private static final int COLOR_BG        = Color.parseColor("#121212");
    private static final int COLOR_SURFACE   = Color.parseColor("#2A2A3E");
    private static final int COLOR_PRIMARY   = Color.parseColor("#7C3AED");
    private static final int COLOR_SECONDARY = Color.parseColor("#9D4EDD");
    private static final int COLOR_TEXT      = Color.parseColor("#E2E8F0");
    private static final int COLOR_TEXT_SEC  = Color.parseColor("#94A3B8");
    private static final int COLOR_SUCCESS   = Color.parseColor("#22C55E");
    private static final int COLOR_ERROR     = Color.parseColor("#EF4444");
    private static final int COLOR_WARNING   = Color.parseColor("#F59E0B");

    // ── UI References ──────────────────────────────────────────────
    private TextView serverStatusText;
    private TextView portText;
    private TextView requestCountText;
    private TextView activeAuthsText;
    private TextView totalTokensText;
    private TextView providersText;

    /** Colored dot drawn on the server-status line. */
    private ViewGroup statusDot;

    @Nullable
    @Override
    public ViewGroup onCreateView(@NonNull android.view.LayoutInflater inflater,
                                   @Nullable ViewGroup container,
                                   @Nullable Bundle savedInstanceState) {
        ScrollView scrollView = new ScrollView(requireContext());
        scrollView.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
        scrollView.setPadding(20, 20, 20, 20);
        scrollView.setBackgroundColor(COLOR_BG);

        LinearLayout root = new LinearLayout(requireContext());
        root.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        root.setOrientation(LinearLayout.VERTICAL);

        // ── Header ─────────────────────────────────────────────────
        root.addView(createTitle("Dashboard"));

        // ── Server Status Card ──────────────────────────────────────
        statusDot = new LinearLayout(requireContext());
        serverStatusText = new TextView(requireContext());
        portText = new TextView(requireContext());
        root.addView(createServerStatusCard());

        // ── Quick Stats Cards (row of 3) ────────────────────────────
        requestCountText = new TextView(requireContext());
        activeAuthsText = new TextView(requireContext());
        totalTokensText = new TextView(requireContext());
        root.addView(createStatsRow());

        // ── Providers Overview Card ─────────────────────────────────
        providersText = new TextView(requireContext());
        root.addView(createProvidersCard());

        scrollView.addView(root);
        return scrollView;
    }

    @Override
    public void onResume() {
        super.onResume();
        refreshData();
    }

    // =================================================================
    //  Data refresh
    // =================================================================

    private void refreshData() {
        ConfigManager config = ConfigManager.getInstance();
        AuthManager authManager = AuthManager.getInstance();

        // Server status – always "running" for now; the dot and text
        // reflect the actual state.
        boolean isRunning = true;
        setStatusDotColor(isRunning ? COLOR_SUCCESS : COLOR_ERROR);
        setText(serverStatusText, isRunning ? "Running" : "Stopped",
                isRunning ? COLOR_SUCCESS : COLOR_ERROR);
        setText(portText, "Port: " + config.getInt("port", 8317),
                COLOR_TEXT_SEC);

        // Quick stats
        setText(requestCountText, "0", COLOR_TEXT);
        setText(activeAuthsText, String.valueOf(authManager.getActiveCount()),
                COLOR_TEXT);
        setText(totalTokensText, "0", COLOR_TEXT);

        // Providers
        int total = authManager.getTotalCount();
        setText(providersText, total > 0 ? total + " configured" : "\u5C1A\u672A\u914D\u7F6E\u63D0\u4F9B\u5546",
                total > 0 ? COLOR_TEXT : COLOR_TEXT_SEC);
    }

    // =================================================================
    //  View builders
    // =================================================================

    /** Page title. */
    private TextView createTitle(String text) {
        TextView tv = new TextView(requireContext());
        tv.setText(text);
        tv.setTextSize(26);
        tv.setTextColor(COLOR_TEXT);
        tv.setTypeface(null, android.graphics.Typeface.BOLD);
        tv.setPadding(0, 0, 0, 20);
        return tv;
    }

    // ── Server Status Card ───────────────────────────────────────────

    private CardView createServerStatusCard() {
        CardView card = baseCard();

        LinearLayout content = new LinearLayout(requireContext());
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(20, 20, 20, 20);

        // Section header with icon-style accent bar
        content.addView(sectionHeader("\u670D\u52A1\u5668\u72B6\u6001"));

        // Status row: dot + "Running"/"Stopped"
        LinearLayout statusRow = new LinearLayout(requireContext());
        statusRow.setOrientation(LinearLayout.HORIZONTAL);
        statusRow.setGravity(Gravity.CENTER_VERTICAL);
        statusRow.setPadding(0, 8, 0, 8);

        // Colored dot
        GradientDrawable dotShape = new GradientDrawable();
        dotShape.setShape(GradientDrawable.OVAL);
        dotShape.setSize(14, 14);
        dotShape.setColor(COLOR_SUCCESS);
        statusDot.setLayoutParams(new LinearLayout.LayoutParams(14, 14));
        statusDot.setBackground(dotShape);

        LinearLayout.LayoutParams dotMargin = new LinearLayout.LayoutParams(14, 14);
        dotMargin.setMargins(0, 0, 10, 0);
        statusDot.setLayoutParams(dotMargin);

        // server-status label
        serverStatusText.setTextSize(18);
        serverStatusText.setTypeface(null, android.graphics.Typeface.BOLD);
        serverStatusText.setTextColor(COLOR_SUCCESS);

        statusRow.addView(statusDot);
        statusRow.addView(serverStatusText);

        content.addView(statusRow);

        // Port line
        portText.setTextSize(14);
        portText.setTextColor(COLOR_TEXT_SEC);
        portText.setPadding(0, 2, 0, 0);
        content.addView(portText);

        card.addView(content);
        return card;
    }

    // ── Quick Stats Row (3 mini-cards) ───────────────────────────────

    private LinearLayout createStatsRow() {
        LinearLayout row = new LinearLayout(requireContext());
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        // margin bottom handled by last child's padding

        int margin = 6;
        row.addView(makeStatCard("Requests\nToday", requestCountText, margin, true));
        row.addView(makeStatCard("Tokens\nToday", totalTokensText, margin, false));
        row.addView(makeStatCard("Active\nAuths", activeAuthsText, margin, false));

        row.setPadding(0, 0, 0, 12);
        return row;
    }

    private CardView makeStatCard(String label, TextView valueView,
                                  int margin, boolean isFirst) {
        CardView card = new CardView(requireContext());
        card.setCardBackgroundColor(COLOR_SURFACE);
        card.setRadius(14);
        card.setCardElevation(0);
        card.setUseCompatPadding(false);

        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        lp.setMargins(isFirst ? 0 : margin, 0, margin, 0);
        card.setLayoutParams(lp);

        LinearLayout inner = new LinearLayout(requireContext());
        inner.setOrientation(LinearLayout.VERTICAL);
        inner.setGravity(Gravity.CENTER);
        inner.setPadding(12, 16, 12, 16);

        // Value
        valueView.setTextSize(24);
        valueView.setTypeface(null, android.graphics.Typeface.BOLD);
        valueView.setTextColor(COLOR_TEXT);
        valueView.setGravity(Gravity.CENTER);
        inner.addView(valueView);

        // Label
        TextView labelView = new TextView(requireContext());
        labelView.setText(label);
        labelView.setTextSize(11);
        labelView.setTextColor(COLOR_TEXT_SEC);
        labelView.setGravity(Gravity.CENTER);
        labelView.setPadding(0, 4, 0, 0);
        inner.addView(labelView);

        card.addView(inner);
        return card;
    }

    // ── Providers Overview Card ──────────────────────────────────────

    private CardView createProvidersCard() {
        CardView card = baseCard();

        LinearLayout content = new LinearLayout(requireContext());
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(20, 20, 20, 20);

        content.addView(sectionHeader("Providers Overview"));

        providersText.setTextSize(15);
        providersText.setTextColor(COLOR_TEXT);
        providersText.setPadding(0, 8, 0, 0);
        content.addView(providersText);

        card.addView(content);
        return card;
    }

    // =================================================================
    //  Shared helpers
    // =================================================================

    /** Base card with MD3 surface styling. */
    private CardView baseCard() {
        CardView card = new CardView(requireContext());
        card.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        card.setCardBackgroundColor(COLOR_SURFACE);
        card.setRadius(16);
        card.setCardElevation(0);
        card.setUseCompatPadding(true);

        LinearLayout.LayoutParams marginParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        marginParams.setMargins(0, 0, 0, 12);
        card.setLayoutParams(marginParams);
        return card;
    }

    /** Section header with an accent underline. */
    private LinearLayout sectionHeader(String title) {
        LinearLayout wrapper = new LinearLayout(requireContext());
        wrapper.setOrientation(LinearLayout.VERTICAL);

        TextView tv = new TextView(requireContext());
        tv.setText(title);
        tv.setTextSize(16);
        tv.setTextColor(COLOR_SECONDARY);
        tv.setTypeface(null, android.graphics.Typeface.BOLD);
        wrapper.addView(tv);

        // Accent bar (thin line below title)
        ViewGroup bar = new ViewGroup(requireContext()) {
            @Override
            protected void onLayout(boolean changed, int l, int t, int r, int b) {
                // no-op; drawable-only view
            }
        };
        bar.setLayoutParams(new LinearLayout.LayoutParams(40, 3));
        bar.setPadding(0, 4, 0, 8);

        GradientDrawable line = new GradientDrawable();
        line.setShape(GradientDrawable.RECTANGLE);
        line.setCornerRadius(2);
        line.setColor(COLOR_PRIMARY);
        bar.setBackground(line);

        wrapper.addView(bar);
        return wrapper;
    }

    /** Update the status dot colour. */
    private void setStatusDotColor(int color) {
        if (statusDot != null && statusDot.getBackground() instanceof GradientDrawable) {
            ((GradientDrawable) statusDot.getBackground()).setColor(color);
        }
    }

    /** Set text and colour on a TextView. */
    private void setText(TextView tv, String text, int color) {
        if (tv != null) {
            tv.setText(text);
            tv.setTextColor(color);
        }
    }
}