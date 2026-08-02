package com.cliproxy.plus.ui.apikeys;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

/**
 * APIKeysFragment - API Key 管理
 * 管理 Claude/Codex/Gemini/xAI/Vertex/OpenAI-Compat 的 API Key
 */
public class APIKeysFragment extends Fragment {

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        TextView textView = new TextView(requireContext());
        textView.setText("API Keys - 密钥管理\n等待实现");
        textView.setTextColor(0xFFCDD6F4);
        textView.setBackgroundColor(0xFF1E1E2E);
        textView.setPadding(24, 24, 24, 24);
        textView.setTextSize(16);
        return textView;
    }
}