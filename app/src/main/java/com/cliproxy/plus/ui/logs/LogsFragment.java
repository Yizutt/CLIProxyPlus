package com.cliproxy.plus.ui.logs;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

/**
 * LogsFragment - 日志查看
 * 实时日志流、错误日志过滤、搜索
 */
public class LogsFragment extends Fragment {

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        TextView textView = new TextView(requireContext());
        textView.setText("Logs - 日志\n等待实现");
        textView.setTextColor(0xFFCDD6F4);
        textView.setBackgroundColor(0xFF1E1E2E);
        textView.setPadding(24, 24, 24, 24);
        textView.setTextSize(16);
        return textView;
    }
}