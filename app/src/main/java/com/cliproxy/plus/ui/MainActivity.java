package com.cliproxy.plus.ui;

import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.Fragment;
import androidx.viewpager2.adapter.FragmentStateAdapter;
import androidx.viewpager2.widget.ViewPager2;

import com.cliproxy.plus.config.ConfigManager;
import com.cliproxy.plus.proxy.ProxyService;
import com.cliproxy.plus.ui.dashboard.DashboardFragment;
import com.cliproxy.plus.ui.config.ConfigFragment;
import com.cliproxy.plus.ui.auth.AuthFragment;
import com.cliproxy.plus.ui.apikeys.APIKeysFragment;
import com.cliproxy.plus.ui.oauth.OAuthFragment;
import com.cliproxy.plus.ui.usage.UsageFragment;
import com.cliproxy.plus.ui.logs.LogsFragment;
import com.cliproxy.plus.ui.agent.AgentFragment;

import java.util.ArrayList;
import java.util.List;

/**
 * CLIProxy Plus 主界面 - 底部导航 + 页面切换
 * 复刻原版 Web 面板的深色紫罗兰风格
 */
public class MainActivity extends AppCompatActivity {

    private ViewPager2 viewPager;
    private ViewPagerAdapter adapter;
    private LinearLayout bottomNav;
    private int activeTab = 0;

    private static final String[] TAB_NAMES = {
        "Dashboard", "Config", "Auth", "Keys", "OAuth", "Usage", "Logs", "Agent"
    };
    private static final String[] TAB_ICONS = {
        "\u2302", "\u2699", "\uD83D\uDD11", "\uD83D\uDDDD", "\uD83D\uDD12", "\uD83D\uDCCA", "\uD83D\uDCDD", "\uD83E\uDD16"
    };
    private static final int[] TAB_COLORS = {
        0xFF7C3AED, 0xFF3B82F6, 0xFF22C55E, 0xFFF59E0B, 0xFFEF4444, 0xFF06B6D4, 0xFF8B5CF6, 0xFFEC4899
    };

    private final List<TextView> tabLabels = new ArrayList<>();
    private final List<TextView> tabIcons = new ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ConfigManager.getInstance(this);

        LinearLayout root = new LinearLayout(this);
        root.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(0xFF1E1E2E);

        // 顶部状态栏
        LinearLayout topBar = new LinearLayout(this);
        topBar.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dpToPx(52)));
        topBar.setOrientation(LinearLayout.HORIZONTAL);
        topBar.setGravity(Gravity.CENTER_VERTICAL);
        topBar.setPadding(dpToPx(16), dpToPx(8), dpToPx(16), dpToPx(8));
        topBar.setBackgroundColor(0xFF7C3AED);

        TextView title = new TextView(this);
        title.setText("CLIProxy Plus");
        title.setTextColor(Color.WHITE);
        title.setTextSize(18);
        title.setTypeface(null, Typeface.BOLD);
        topBar.addView(title);

        TextView statusDot = new TextView(this);
        statusDot.setText("\u25CF");
        statusDot.setTextColor(0xFF22C55E);
        statusDot.setTextSize(10);
        statusDot.setPadding(dpToPx(8), 0, 0, 0);
        topBar.addView(statusDot);

        TextView versionText = new TextView(this);
        versionText.setText("v6.9.45");
        versionText.setTextColor(0xCCFFFFFF);
        versionText.setTextSize(12);
        versionText.setPadding(dpToPx(8), dpToPx(2), 0, 0);
        topBar.addView(versionText);

        root.addView(topBar);

        // ViewPager2
        viewPager = new ViewPager2(this);
        viewPager.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        viewPager.setId(android.R.id.content);

        // 底部导航栏
        bottomNav = new LinearLayout(this);
        bottomNav.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dpToPx(64)));
        bottomNav.setOrientation(LinearLayout.HORIZONTAL);
        bottomNav.setBackgroundColor(0xFF1E1E2E);

        for (int i = 0; i < TAB_NAMES.length; i++) {
            final int index = i;
            LinearLayout tabItem = new LinearLayout(this);
            tabItem.setLayoutParams(new LinearLayout.LayoutParams(
                    0, ViewGroup.LayoutParams.MATCH_PARENT, 1f));
            tabItem.setOrientation(LinearLayout.VERTICAL);
            tabItem.setGravity(Gravity.CENTER);
            tabItem.setPadding(0, dpToPx(4), 0, dpToPx(4));
            tabItem.setBackgroundColor(0xFF1E1E2E);
            tabItem.setClickable(true);
            tabItem.setOnClickListener(v -> selectTab(index));

            TextView iconView = new TextView(this);
            iconView.setText(TAB_ICONS[i]);
            iconView.setTextSize(18);
            iconView.setGravity(Gravity.CENTER);
            iconView.setTextColor(0xFFA6ADC8);

            TextView labelView = new TextView(this);
            labelView.setText(TAB_NAMES[i]);
            labelView.setTextSize(9);
            labelView.setGravity(Gravity.CENTER);
            labelView.setTextColor(0xFFA6ADC8);

            tabItem.addView(iconView);
            tabItem.addView(labelView);
            tabIcons.add(iconView);
            tabLabels.add(labelView);
            bottomNav.addView(tabItem);
        }

        root.addView(viewPager);
        root.addView(bottomNav);
        setContentView(root);

        setupViewPager();
        selectTab(0);
        startProxyService();
    }

    private void setupViewPager() {
        adapter = new ViewPagerAdapter(this);
        adapter.addFragment(new DashboardFragment());
        adapter.addFragment(new ConfigFragment());
        adapter.addFragment(new AuthFragment());
        adapter.addFragment(new APIKeysFragment());
        adapter.addFragment(new OAuthFragment());
        adapter.addFragment(new UsageFragment());
        adapter.addFragment(new LogsFragment());
        adapter.addFragment(new AgentFragment());
        viewPager.setAdapter(adapter);
        viewPager.setOffscreenPageLimit(1);
        viewPager.registerOnPageChangeCallback(new ViewPager2.OnPageChangeCallback() {
            @Override public void onPageSelected(int position) { selectTab(position); }
        });
    }

    private void selectTab(int index) {
        activeTab = index;
        viewPager.setCurrentItem(index, false);
        for (int i = 0; i < tabIcons.size(); i++) {
            int color = (i == index) ? TAB_COLORS[i] : 0xFFA6ADC8;
            tabIcons.get(i).setTextColor(color);
            tabLabels.get(i).setTextColor(color);
            tabLabels.get(i).setTypeface(null, (i == index) ? Typeface.BOLD : Typeface.NORMAL);
        }
    }

    private void startProxyService() {
        Intent intent = new Intent(this, ProxyService.class);
        intent.setAction("START");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent);
        } else {
            startService(intent);
        }
    }

    private int dpToPx(int dp) {
        float density = getResources().getDisplayMetrics().density;
        return Math.round(dp * density);
    }

    static class ViewPagerAdapter extends FragmentStateAdapter {
        private final List<Fragment> fragments = new ArrayList<>();
        public ViewPagerAdapter(MainActivity a) { super(a); }
        public void addFragment(Fragment f) { fragments.add(f); }
        @Override public Fragment createFragment(int p) { return fragments.get(p); }
        @Override public int getItemCount() { return fragments.size(); }
    }
}