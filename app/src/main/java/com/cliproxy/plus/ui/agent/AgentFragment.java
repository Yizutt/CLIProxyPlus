package com.cliproxy.plus.ui.agent;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

/**
 * AgentFragment - AI Agent 助手
 * 聊天界面，自然语言交互管理 App
 */
public class AgentFragment extends Fragment {

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        TextView textView = new TextView(requireContext());
        textView.setText("AI Agent - 智能助手\n等待实现");
        textView.setTextColor(0xFFCDD6F4);
        textView.setBackgroundColor(0xFF1E1E2E);
        textView.setPadding(24, 24, 24, 24);
        textView.setTextSize(16);
        return textView;
    }
}