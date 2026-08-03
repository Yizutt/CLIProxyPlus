package com.cliproxy.plus.ui;

import android.content.Intent;
import android.graphics.Color;
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

public class MainActivity extends AppCompatActivity {

    private ViewPager2 viewPager;
    private ViewPagerAdapter adapter;
    private LinearLayout bottomNav;
    private final String[] tabNames = {"Dashboard", "Config", "Auth", "API Keys", "OAuth", "Usage", "Logs", "Agent"};
    private final List<TextView> tabViews = new ArrayList<>();
    private int activeTab = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // 初始化 ConfigManager
        ConfigManager.getInstance(this);

        // 纯 Java 构建 UI
        LinearLayout root = new LinearLayout(this);
        root.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.parseColor("#1E1E2E"));

        // ViewPager2
        viewPager = new ViewPager2(this);
        viewPager.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0, 1f));
        viewPager.setId(android.R.id.content);

        // BottomNavigationView 替换为纯 LinearLayout
        bottomNav = new LinearLayout(this);
        bottomNav.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                dpToPx(56)));
        bottomNav.setOrientation(LinearLayout.HORIZONTAL);
        bottomNav.setBackgroundColor(Color.parseColor("#313244"));
        bottomNav.setGravity(Gravity.CENTER);

        // 创建 Tab 按钮
        for (int i = 0; i < tabNames.length; i++) {
            final int index = i;
            TextView tab = new TextView(this);
            LinearLayout.LayoutParams tabParams = new LinearLayout.LayoutParams(
                    0, ViewGroup.LayoutParams.MATCH_PARENT, 1f);
            tab.setLayoutParams(tabParams);
            tab.setText(tabNames[i]);
            tab.setTextSize(10);
            tab.setGravity(Gravity.CENTER);
            tab.setTextColor(Color.parseColor("#A6ADC8"));
            tab.setPadding(2, 4, 2, 4);
            tab.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    selectTab(index);
                }
            });
            tabViews.add(tab);
            bottomNav.addView(tab);
        }

        root.addView(viewPager);
        root.addView(bottomNav);
        setContentView(root);

        setupViewPager();
        selectTab(0);

        // 启动服务
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
            @Override
            public void onPageSelected(int position) {
                super.onPageSelected(position);
                selectTab(position);
            }
        });
    }

    private void selectTab(int index) {
        activeTab = index;
        viewPager.setCurrentItem(index, false);
        for (int i = 0; i < tabViews.size(); i++) {
            if (i == index) {
                tabViews.get(i).setTextColor(Color.parseColor("#7C3AED"));
                tabViews.get(i).setTypeface(null, android.graphics.Typeface.BOLD);
            } else {
                tabViews.get(i).setTextColor(Color.parseColor("#A6ADC8"));
                tabViews.get(i).setTypeface(null, android.graphics.Typeface.NORMAL);
            }
        }
    }

    private int dpToPx(int dp) {
        float density = getResources().getDisplayMetrics().density;
        return Math.round(dp * density);
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

    static class ViewPagerAdapter extends FragmentStateAdapter {
        private final List<Fragment> fragments = new ArrayList<>();

        public ViewPagerAdapter(MainActivity activity) {
            super(activity);
        }

        public void addFragment(Fragment fragment) {
            fragments.add(fragment);
        }

        @Override
        public Fragment createFragment(int position) {
            return fragments.get(position);
        }

        @Override
        public int getItemCount() {
            return fragments.size();
        }
    }
}