package com.cliproxy.plus.ui;

import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.view.MenuItem;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.Fragment;
import androidx.viewpager2.adapter.FragmentStateAdapter;
import androidx.viewpager2.widget.ViewPager2;

import com.cliproxy.plus.R;
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
import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.google.android.material.navigation.NavigationBarView;

import java.util.ArrayList;
import java.util.List;

/**
 * MainActivity - 主入口
 * 底部导航栏 + ViewPager2 切换页面
 * 对应原版 TUI 的 Tab 栏
 */
public class MainActivity extends AppCompatActivity {

    private BottomNavigationView bottomNav;
    private ViewPager2 viewPager;
    private ViewPagerAdapter adapter;
    private boolean serverRunning = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        bottomNav = findViewById(R.id.bottom_navigation);
        viewPager = findViewById(R.id.view_pager);

        // 初始化 ConfigManager
        ConfigManager.getInstance(this);

        setupViewPager();
        setupBottomNav();

        // 默认启动服务器
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
                bottomNav.getMenu().getItem(position).setChecked(true);
            }
        });
    }

    private void setupBottomNav() {
        bottomNav.setOnItemSelectedListener(new NavigationBarView.OnItemSelectedListener() {
            @Override
            public boolean onNavigationItemSelected(@NonNull MenuItem item) {
                int id = item.getItemId();
                if (id == R.id.nav_dashboard) viewPager.setCurrentItem(0);
                else if (id == R.id.nav_config) viewPager.setCurrentItem(1);
                else if (id == R.id.nav_auth) viewPager.setCurrentItem(2);
                else if (id == R.id.nav_apikeys) viewPager.setCurrentItem(3);
                else if (id == R.id.nav_oauth) viewPager.setCurrentItem(4);
                else if (id == R.id.nav_usage) viewPager.setCurrentItem(5);
                else if (id == R.id.nav_logs) viewPager.setCurrentItem(6);
                else if (id == R.id.nav_agent) viewPager.setCurrentItem(7);
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
        serverRunning = true;
    }

    private void stopProxyService() {
        Intent intent = new Intent(this, ProxyService.class);
        intent.setAction("STOP");
        stopService(intent);
        serverRunning = false;
    }

    public boolean isServerRunning() {
        return serverRunning;
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
    }

    /**
     * ViewPager2 适配器（使用 FragmentStateAdapter）
     */
    static class ViewPagerAdapter extends FragmentStateAdapter {
        private final List<Fragment> fragments = new ArrayList<>();

        public ViewPagerAdapter(MainActivity activity) {
            super(activity);
        }

        public void addFragment(Fragment fragment) {
            fragments.add(fragment);
        }

        @NonNull
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