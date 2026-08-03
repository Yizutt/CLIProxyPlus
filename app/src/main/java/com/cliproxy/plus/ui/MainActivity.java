package com.cliproxy.plus.ui;

import android.content.Intent;
import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.LinearLayout;

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
import com.google.android.material.bottomnavigation.BottomNavigationItemView;
import com.google.android.material.bottomnavigation.BottomNavigationMenuView;
import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.google.android.material.navigation.NavigationBarView;

import java.util.ArrayList;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    private BottomNavigationView bottomNav;
    private ViewPager2 viewPager;
    private ViewPagerAdapter adapter;

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

        // BottomNavigationView
        bottomNav = new BottomNavigationView(this);
        bottomNav.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        bottomNav.setBackgroundColor(Color.parseColor("#1E1E2E"));
        bottomNav.setItemIconTintList(null);
        bottomNav.setItemTextColor(null);

        root.addView(viewPager);
        root.addView(bottomNav);
        setContentView(root);

        setupViewPager();
        setupBottomNav();

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
                if (bottomNav.getMenu().size() > position) {
                    bottomNav.getMenu().getItem(position).setChecked(true);
                }
            }
        });
    }

    private void setupBottomNav() {
        bottomNav.getMenu().add(0, 1, 0, "Dashboard");
        bottomNav.getMenu().add(0, 2, 0, "Config");
        bottomNav.getMenu().add(0, 3, 0, "Auth");
        bottomNav.getMenu().add(0, 4, 0, "API Keys");
        bottomNav.getMenu().add(0, 5, 0, "OAuth");
        bottomNav.getMenu().add(0, 6, 0, "Usage");
        bottomNav.getMenu().add(0, 7, 0, "Logs");
        bottomNav.getMenu().add(0, 8, 0, "Agent");

        bottomNav.setOnItemSelectedListener(new NavigationBarView.OnItemSelectedListener() {
            @Override
            public boolean onNavigationItemSelected(android.view.MenuItem item) {
                int id = item.getItemId();
                int index = id - 1;
                if (index >= 0 && index < adapter.getItemCount()) {
                    viewPager.setCurrentItem(index);
                }
                return true;
            }
        });
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