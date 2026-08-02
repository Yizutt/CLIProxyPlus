package com.cliproxy.plus.ui.dashboard;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.cliproxy.plus.R;
import com.cliproxy.plus.auth.AuthManager;
import com.cliproxy.plus.config.ConfigManager;

/**
 * DashboardFragment - 仪表盘
 * 显示服务器状态、请求统计、账号概览
 */
public class DashboardFragment extends Fragment {

    private TextView serverStatusText;
    private TextView requestCountText;
    private TextView activeAuthsText;
    private TextView portText;
    private TextView totalTokensText;
    private TextView providersListText;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_dashboard, container, false);
        serverStatusText = view.findViewById(R.id.server_status);
        requestCountText = view.findViewById(R.id.request_count);
        activeAuthsText = view.findViewById(R.id.active_auths);
        portText = view.findViewById(R.id.port_info);
        totalTokensText = view.findViewById(R.id.total_tokens);
        providersListText = view.findViewById(R.id.providers_list);
        return view;
    }

    @Override
    public void onResume() {
        super.onResume();
        refreshData();
    }

    private void refreshData() {
        ConfigManager config = ConfigManager.getInstance();
        AuthManager authManager = AuthManager.getInstance();

        if (serverStatusText != null) {
            serverStatusText.setText("服务器状态: 运行中");
            serverStatusText.setTextColor(0xFF22C55E); // 绿色
        }
        if (portText != null) {
            portText.setText("端口: " + config.getInt("port", 8317));
        }
        if (requestCountText != null) {
            requestCountText.setText("今日请求: 0");
        }
        if (activeAuthsText != null) {
            activeAuthsText.setText("活跃账号: " + authManager.getActiveCount());
        }
        if (totalTokensText != null) {
            totalTokensText.setText("总 Token 消耗: 0");
        }
        if (providersListText != null) {
            int total = authManager.getTotalCount();
            providersListText.setText(total > 0 ? "已配置 " + total + " 个凭证" : "暂无配置");
        }
    }
}