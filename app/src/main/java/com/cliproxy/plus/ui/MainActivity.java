package com.cliproxy.plus.ui;

import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.drawerlayout.widget.DrawerLayout;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.fragment.app.FragmentTransaction;

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
 * CLIProxy Plus 主界面 — DrawerLayout 侧边栏导航
 * 现代化 Material Design 3 暗色风格
 */
public class MainActivity extends AppCompatActivity {

    private DrawerLayout drawerLayout;
    private LinearLayout drawerMenu;
    private FrameLayout contentFrame;
    private TextView titleText;
    private View statusIndicator;

    private final List<NavItem> navItems = new ArrayList<>();
    private int activeNavIndex = 0;
    private Fragment activeFragment;

    static class NavItem {
        String icon;
        String label;
        Fragment fragment;
        NavItem(String icon, String label, Fragment fragment) {
            this.icon = icon; this.label = label; this.fragment = fragment;
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ConfigManager.getInstance(this);

        // 导航项
        navItems.add(new NavItem("\u25A0", "Dashboard", new DashboardFragment()));
        navItems.add(new NavItem("\u2699", "Config", new ConfigFragment()));
        navItems.add(new NavItem("\uD83D\uDD11", "Auth Files", new AuthFragment()));
        navItems.add(new NavItem("\uD83D\uDDDD", "API Keys", new APIKeysFragment()));
        navItems.add(new NavItem("\uD83D\uDD12", "OAuth", new OAuthFragment()));
        navItems.add(new NavItem("\uD83D\uDCCA", "Usage", new UsageFragment()));
        navItems.add(new NavItem("\uD83D\uDCDD", "Logs", new LogsFragment()));
        navItems.add(new NavItem("\uD83E\uDD16", "Agent", new AgentFragment()));

        // DrawerLayout
        drawerLayout = new DrawerLayout(this);
        drawerLayout.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
        drawerLayout.setBackgroundColor(0xFF121212);

        // ====== 主内容区 ======
        LinearLayout mainContent = new LinearLayout(this);
        mainContent.setLayoutParams(new DrawerLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
        mainContent.setOrientation(LinearLayout.VERTICAL);

        // AppBar
        LinearLayout appBar = new LinearLayout(this);
        appBar.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dpToPx(56)));
        appBar.setOrientation(LinearLayout.HORIZONTAL);
        appBar.setGravity(Gravity.CENTER_VERTICAL);
        appBar.setBackgroundColor(0xFF7C3AED);
        appBar.setPadding(dpToPx(8), dpToPx(4), dpToPx(16), dpToPx(4));

        // 汉堡菜单按钮
        TextView menuBtn = new TextView(this);
        menuBtn.setText("\u2630");
        menuBtn.setTextSize(22);
        menuBtn.setTextColor(Color.WHITE);
        menuBtn.setPadding(dpToPx(12), dpToPx(8), dpToPx(12), dpToPx(8));
        menuBtn.setOnClickListener(v -> drawerLayout.openDrawer(Gravity.START));
        appBar.addView(menuBtn);

        // 标题
        titleText = new TextView(this);
        titleText.setText("CLIProxy Plus");
        titleText.setTextColor(Color.WHITE);
        titleText.setTextSize(18);
        titleText.setTypeface(null, Typeface.BOLD);
        titleText.setPadding(dpToPx(8), 0, 0, 0);
        appBar.addView(titleText);

        // 状态指示器
        statusIndicator = new View(this);
        statusIndicator.setLayoutParams(new LinearLayout.LayoutParams(dpToPx(10), dpToPx(10)));
        ((LinearLayout.LayoutParams)statusIndicator.getLayoutParams()).setMargins(dpToPx(12), 0, 0, 0);
        ((LinearLayout.LayoutParams)statusIndicator.getLayoutParams()).gravity = Gravity.CENTER_VERTICAL;
        statusIndicator.setBackgroundResource(android.R.drawable.presence_online);
        statusIndicator.setBackgroundColor(0xFF22C55E);
        appBar.addView(statusIndicator);

        mainContent.addView(appBar);

        // 内容 FrameLayout
        contentFrame = new FrameLayout(this);
        contentFrame.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        contentFrame.setId(View.generateViewId());
        mainContent.addView(contentFrame);

        drawerLayout.addView(mainContent);

        // ====== 侧边栏 ======
        LinearLayout drawerView = new LinearLayout(this);
        DrawerLayout.LayoutParams drawerParams = new DrawerLayout.LayoutParams(
                dpToPx(280), ViewGroup.LayoutParams.MATCH_PARENT);
        drawerParams.gravity = Gravity.START;
        drawerView.setLayoutParams(drawerParams);
        drawerView.setOrientation(LinearLayout.VERTICAL);
        drawerView.setBackgroundColor(0xFF1A1A2E);

        // 侧边栏头部
        LinearLayout drawerHeader = new LinearLayout(this);
        drawerHeader.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dpToPx(160)));
        drawerHeader.setOrientation(LinearLayout.VERTICAL);
        drawerHeader.setGravity(Gravity.CENTER);
        drawerHeader.setBackgroundColor(0xFF7C3AED);

        TextView appIcon = new TextView(this);
        appIcon.setText("\u25A0\u25A0");
        appIcon.setTextSize(36);
        appIcon.setTextColor(Color.WHITE);
        appIcon.setPadding(0, dpToPx(24), 0, dpToPx(8));
        drawerHeader.addView(appIcon);

        TextView appName = new TextView(this);
        appName.setText("CLIProxy Plus");
        appName.setTextColor(Color.WHITE);
        appName.setTextSize(20);
        appName.setTypeface(null, Typeface.BOLD);
        drawerHeader.addView(appName);

        TextView appVersion = new TextView(this);
        appVersion.setText("v6.9.45 \u00B7 ARM64");
        appVersion.setTextColor(0xCCFFFFFF);
        appVersion.setTextSize(12);
        appVersion.setPadding(0, dpToPx(4), 0, 0);
        drawerHeader.addView(appVersion);

        drawerView.addView(drawerHeader);

        // 导航菜单列表
        ScrollView menuScroll = new ScrollView(this);
        menuScroll.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        LinearLayout menuList = new LinearLayout(this);
        menuList.setOrientation(LinearLayout.VERTICAL);
        menuList.setPadding(0, dpToPx(8), 0, dpToPx(8));

        for (int i = 0; i < navItems.size(); i++) {
            final int index = i;
            NavItem item = navItems.get(i);

            LinearLayout navRow = new LinearLayout(this);
            navRow.setLayoutParams(new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, dpToPx(48)));
            navRow.setOrientation(LinearLayout.HORIZONTAL);
            navRow.setGravity(Gravity.CENTER_VERTICAL);
            navRow.setPadding(dpToPx(20), 0, dpToPx(20), 0);
            navRow.setClickable(true);
            navRow.setOnClickListener(v -> {
                selectNavItem(index);
                drawerLayout.closeDrawer(Gravity.START);
            });

            TextView iconView = new TextView(this);
            iconView.setText(item.icon);
            iconView.setTextSize(18);
            iconView.setWidth(dpToPx(32));
            iconView.setTextColor(0xFF94A3B8);

            TextView labelView = new TextView(this);
            labelView.setText(item.label);
            labelView.setTextSize(15);
            labelView.setTextColor(0xFFE2E8F0);
            labelView.setPadding(dpToPx(12), 0, 0, 0);

            navRow.addView(iconView);
            navRow.addView(labelView);
            menuList.addView(navRow);
        }

        menuScroll.addView(menuList);
        drawerView.addView(menuScroll);

        // 底部版本信息
        TextView footerText = new TextView(this);
        footerText.setText("Build with \u2764 for Android");
        footerText.setTextColor(0xFF475569);
        footerText.setTextSize(11);
        footerText.setGravity(Gravity.CENTER);
        footerText.setPadding(0, dpToPx(12), 0, dpToPx(16));
        drawerView.addView(footerText);

        drawerLayout.addView(drawerView);

        setContentView(drawerLayout);

        // 默认显示第一个 Fragment
        selectNavItem(0);
        startProxyService();
    }

    private void selectNavItem(int index) {
        if (index == activeNavIndex && activeFragment != null) return;
        activeNavIndex = index;
        NavItem item = navItems.get(index);
        titleText.setText(item.label);

        FragmentTransaction ft = getSupportFragmentManager().beginTransaction();
        ft.setCustomAnimations(android.R.anim.fade_in, android.R.anim.fade_out);
        ft.replace(contentFrame.getId(), item.fragment, item.label);
        ft.commit();
        activeFragment = item.fragment;
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
}