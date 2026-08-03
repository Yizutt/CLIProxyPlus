package com.cliproxy.plus.ui.agent;

import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.cardview.widget.CardView;
import androidx.fragment.app.Fragment;

import com.cliproxy.plus.agent.llm.CustomLLMClient;
import com.cliproxy.plus.config.ConfigManager;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * AgentFragment - AI Agent 聊天界面
 * 纯 Java UI，支持消息收发、打字指示器、清空对话
 */
public class AgentFragment extends Fragment {

    private static final String TAG = "AgentFragment";
    private static final String COLOR_BG = "#1E1E2E";
    private static final String COLOR_PRIMARY = "#7C3AED";
    private static final String COLOR_TEXT = "#CDD6F4";
    private static final String COLOR_MUTED = "#A6ADC8";
    private static final String COLOR_CARD = "#313244";
    private static final String COLOR_USER_BUBBLE = "#7C3AED";
    private static final String COLOR_AGENT_BUBBLE = "#313244";
    private static final String COLOR_AGENT_ACCENT = "#45475A";

    private ListView chatListView;
    private EditText inputEditText;
    private Button sendButton;
    private LinearLayout typingIndicator;
    private Button clearButton;

    private final List<ChatMessage> messages = new ArrayList<>();
    private CustomLLMClient llmClient;
    private ChatAdapter chatAdapter;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    // ===================== Message Model =====================

    private static class ChatMessage {
        final String text;
        final boolean isUser;
        final long timestamp;

        ChatMessage(String text, boolean isUser) {
            this.text = text;
            this.isUser = isUser;
            this.timestamp = System.currentTimeMillis();
        }
    }

    // ===================== Fragment Lifecycle =====================

    @Nullable
    @Override
    public View onCreateView(@NonNull android.view.LayoutInflater inflater,
                             @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        LinearLayout root = new LinearLayout(requireContext());
        root.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.parseColor(COLOR_BG));

        // --- Header ---
        root.addView(createHeader());

        // --- Chat List ---
        chatListView = new ListView(requireContext());
        chatListView.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0, 1f));
        chatListView.setDivider(null);
        chatListView.setDividerHeight(0);
        chatListView.setSelector(android.R.color.transparent);
        chatListView.setVerticalScrollBarEnabled(true);
        chatListView.setPadding(dpToPx(8), dpToPx(8), dpToPx(8), dpToPx(8));

        chatAdapter = new ChatAdapter();
        chatListView.setAdapter(chatAdapter);

        root.addView(chatListView);

        // --- Typing Indicator ---
        typingIndicator = createTypingIndicator();
        root.addView(typingIndicator);

        // --- Input Area ---
        root.addView(createInputArea());

        // Add welcome message
        addMessage("你好！我是 AI 助手，有什么可以帮你的吗？", false);

        return root;
    }

    // ===================== Header =====================

    private LinearLayout createHeader() {
        LinearLayout header = new LinearLayout(requireContext());
        header.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.setPadding(dpToPx(16), dpToPx(12), dpToPx(16), dpToPx(12));
        header.setBackgroundColor(Color.parseColor("#313244"));

        // Title
        TextView title = new TextView(requireContext());
        LinearLayout.LayoutParams titleParams = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        title.setLayoutParams(titleParams);
        title.setText("AI Agent");
        title.setTextSize(18);
        title.setTextColor(Color.parseColor(COLOR_TEXT));
        title.setTypeface(null, Typeface.BOLD);
        header.addView(title);

        // Clear button
        clearButton = new Button(requireContext());
        clearButton.setText("清空");
        clearButton.setTextSize(12);
        clearButton.setTextColor(Color.parseColor(COLOR_TEXT));
        clearButton.setBackgroundColor(Color.parseColor("#45475A"));
        clearButton.setPadding(dpToPx(12), dpToPx(6), dpToPx(12), dpToPx(6));
        clearButton.setMinimumWidth(0);
        clearButton.setMinHeight(0);
        clearButton.setMaxHeight(dpToPx(32));
        clearButton.setGravity(Gravity.CENTER);
        clearButton.setAllCaps(false);
        clearButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                clearChat();
            }
        });
        header.addView(clearButton);

        // Settings button
        Button settingsBtn = new Button(requireContext());
        settingsBtn.setText("\u2699");
        settingsBtn.setTextSize(16);
        settingsBtn.setTextColor(Color.parseColor(COLOR_TEXT));
        settingsBtn.setBackgroundColor(Color.parseColor("#45475A"));
        settingsBtn.setPadding(dpToPx(8), dpToPx(6), dpToPx(8), dpToPx(6));
        settingsBtn.setMinimumWidth(0);
        settingsBtn.setMinHeight(0);
        settingsBtn.setMaxHeight(dpToPx(32));
        settingsBtn.setGravity(Gravity.CENTER);
        android.view.ViewGroup.MarginLayoutParams settingsMargins = (android.view.ViewGroup.MarginLayoutParams) settingsBtn.getLayoutParams();
        if (settingsMargins == null) {
            settingsMargins = new LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.WRAP_CONTENT,
                    android.view.ViewGroup.LayoutParams.WRAP_CONTENT);
        }
        settingsMargins.setMargins(dpToPx(8), 0, 0, 0);
        settingsBtn.setLayoutParams(settingsMargins);
        settingsBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                showConfigDialog();
            }
        });
        header.addView(settingsBtn);

        return header;
    }

    // ===================== Input Area =====================

    private LinearLayout createInputArea() {
        LinearLayout inputArea = new LinearLayout(requireContext());
        inputArea.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        inputArea.setOrientation(LinearLayout.HORIZONTAL);
        inputArea.setGravity(Gravity.CENTER_VERTICAL);
        inputArea.setPadding(dpToPx(8), dpToPx(8), dpToPx(8), dpToPx(8));
        inputArea.setBackgroundColor(Color.parseColor(COLOR_CARD));

        // Input field
        inputEditText = new EditText(requireContext());
        LinearLayout.LayoutParams inputParams = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        inputEditText.setLayoutParams(inputParams);
        inputEditText.setHint("输入消息...");
        inputEditText.setHintTextColor(Color.parseColor(COLOR_MUTED));
        inputEditText.setTextColor(Color.parseColor(COLOR_TEXT));
        inputEditText.setBackgroundColor(Color.parseColor("#45475A"));
        inputEditText.setPadding(dpToPx(12), dpToPx(10), dpToPx(12), dpToPx(10));
        inputEditText.setTextSize(15);
        inputEditText.setSingleLine(false);
        inputEditText.setMaxLines(4);
        inputEditText.setMinHeight(dpToPx(40));
        inputArea.addView(inputEditText);

        // Send button
        sendButton = new Button(requireContext());
        sendButton.setText("发送");
        sendButton.setTextSize(14);
        sendButton.setTextColor(Color.WHITE);
        sendButton.setBackgroundColor(Color.parseColor(COLOR_PRIMARY));
        sendButton.setPadding(dpToPx(16), dpToPx(10), dpToPx(16), dpToPx(10));
        sendButton.setMinWidth(0);
        sendButton.setMinHeight(0);
        sendButton.setGravity(Gravity.CENTER);
        sendButton.setAllCaps(false);
        sendButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                sendMessage();
            }
        });

        LinearLayout.LayoutParams sendParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        sendParams.setMargins(dpToPx(8), 0, 0, 0);
        sendButton.setLayoutParams(sendParams);
        inputArea.addView(sendButton);

        return inputArea;
    }

    // ===================== Typing Indicator =====================

    private LinearLayout createTypingIndicator() {
        LinearLayout indicator = new LinearLayout(requireContext());
        indicator.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        indicator.setOrientation(LinearLayout.HORIZONTAL);
        indicator.setGravity(Gravity.START);
        indicator.setPadding(dpToPx(16), dpToPx(8), dpToPx(16), dpToPx(8));
        indicator.setVisibility(View.GONE);

        LinearLayout bubble = new LinearLayout(requireContext());
        LinearLayout.LayoutParams bubbleParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        bubble.setLayoutParams(bubbleParams);
        bubble.setOrientation(LinearLayout.HORIZONTAL);
        bubble.setBackgroundColor(Color.parseColor(COLOR_AGENT_BUBBLE));
        bubble.setPadding(dpToPx(16), dpToPx(10), dpToPx(16), dpToPx(10));
        setBubbleBackground(bubble, COLOR_AGENT_BUBBLE, false);

        // Three dots
        for (int i = 0; i < 3; i++) {
            TextView dot = new TextView(requireContext());
            dot.setText("●");
            dot.setTextSize(8);
            dot.setTextColor(Color.parseColor(COLOR_MUTED));
            dot.setPadding(dpToPx(2), 0, dpToPx(2), 0);
            bubble.addView(dot);
        }

        indicator.addView(bubble);
        return indicator;
    }

    // ===================== Message Actions =====================

    private void sendMessage() {
        String text = inputEditText.getText().toString().trim();
        if (TextUtils.isEmpty(text)) {
            return;
        }

        inputEditText.setText("");
        addMessage(text, true);
        showTypingIndicator(true);

        if (llmClient != null) {
            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        final String response = llmClient.generateResponse(
                            "You are a helpful assistant for managing CLIProxy Plus proxy server. Answer concisely.",
                            text, new java.util.ArrayList<String>());
                        new Handler(Looper.getMainLooper()).post(new Runnable() {
                            @Override
                            public void run() {
                                showTypingIndicator(false);
                                addMessage(response, false);
                            }
                        });
                    } catch (final Exception e) {
                        new Handler(Looper.getMainLooper()).post(new Runnable() {
                            @Override
                            public void run() {
                                showTypingIndicator(false);
                                addMessage("Error: " + e.getMessage(), false);
                            }
                        });
                    }
                }
            }).start();
        } else {
            new Handler(Looper.getMainLooper()).postDelayed(new Runnable() {
                @Override
                public void run() {
                    showTypingIndicator(false);
                    String response = generateAgentResponse(text);
                    addMessage(response, false);
                }
            }, 800);
        }
    }

    private void clearChat() {
        messages.clear();
        chatAdapter.notifyDataSetChanged();
        showTypingIndicator(false);
        addMessage("对话已清空，开始新的对话吧！", false);
        Log.d(TAG, "Chat cleared");
    }

    private void addMessage(String text, boolean isUser) {
        messages.add(new ChatMessage(text, isUser));
        chatAdapter.notifyDataSetChanged();
        // Scroll to bottom
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                chatListView.setSelection(messages.size() - 1);
            }
        });
    }

    private void showTypingIndicator(boolean show) {
        typingIndicator.setVisibility(show ? View.VISIBLE : View.GONE);
        if (show) {
            mainHandler.post(new Runnable() {
                @Override
                public void run() {
                    chatListView.setSelection(messages.size());
                }
            });
        }
    }

    // ===================== Agent Response Generation =====================

    private String generateAgentResponse(String userMessage) {
        // Simple rule-based responses for demo
        String lower = userMessage.toLowerCase();

        if (lower.contains("你好") || lower.contains("hello") || lower.contains("hi")) {
            return "你好！我是 AI 助手，可以帮你管理代理配置、查看状态、处理 API 请求等。有什么需要帮忙的吗？";
        }
        if (lower.contains("帮助") || lower.contains("help") || lower.contains("功能")) {
            return "我可以帮你：\n1. 查看和管理代理配置\n2. 监控服务器状态\n3. 管理 API 凭证\n4. 查看使用统计\n5. 处理 OAuth 授权\n\n请问你想了解哪方面？";
        }
        if (lower.contains("状态") || lower.contains("status") || lower.contains("运行")) {
            return "当前服务器状态：运行中\n端口：8317\n活跃请求：0\n内存使用：正常\n\n更多详情请查看 Dashboard 页面。";
        }
        if (lower.contains("配置") || lower.contains("config") || lower.contains("设置")) {
            return "代理配置管理：\n- 端口配置：默认 8317\n- 超时设置：30 秒\n- 重试次数：3 次\n- 日志级别：INFO\n\n你可以在 Config 页面修改这些设置。";
        }
        if (lower.contains("api") || lower.contains("密钥") || lower.contains("key") || lower.contains("凭证")) {
            return "API 凭证管理：\n目前支持多种 AI 提供商的 API 密钥管理。你可以在 API Keys 页面添加、查看或删除凭证。\n\n请确保妥善保管你的 API 密钥。";
        }
        if (lower.contains("谢谢") || lower.contains("thank")) {
            return "不客气！如果还有其他问题，随时问我。";
        }
        if (lower.contains("天气") || lower.contains("weather")) {
            return "抱歉，我目前没有联网查询天气的能力。你可以检查网络连接或使用其他工具获取天气信息。";
        }

        // Default response
        return "收到你的消息：「" + userMessage + "」\n\n我还在学习如何更好地回答这个问题。请尝试更具体的描述，或者输入「帮助」查看我能提供的功能。";
    }

    // ===================== Chat Adapter =====================

    private class ChatAdapter extends BaseAdapter {

        @Override
        public int getCount() {
            return messages.size();
        }

        @Override
        public Object getItem(int position) {
            return messages.get(position);
        }

        @Override
        public long getItemId(int position) {
            return position;
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            ChatMessage msg = messages.get(position);

            // Use a container that holds both the message and spacing
            LinearLayout rowContainer;
            if (convertView instanceof LinearLayout) {
                rowContainer = (LinearLayout) convertView;
                rowContainer.removeAllViews();
            } else {
                rowContainer = new LinearLayout(requireContext());
                rowContainer.setLayoutParams(new ListView.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT));
                rowContainer.setOrientation(LinearLayout.VERTICAL);
                rowContainer.setPadding(0, dpToPx(4), 0, dpToPx(4));
            }

            // Message bubble
            LinearLayout bubble = new LinearLayout(requireContext());
            LinearLayout.LayoutParams bubbleParams = new LinearLayout.LayoutParams(
                    dpToPx(280),
                    ViewGroup.LayoutParams.WRAP_CONTENT);
            bubble.setLayoutParams(bubbleParams);
            bubble.setOrientation(LinearLayout.VERTICAL);
            bubble.setPadding(dpToPx(12), dpToPx(10), dpToPx(12), dpToPx(10));
            setBubbleBackground(bubble, msg.isUser ? COLOR_USER_BUBBLE : COLOR_AGENT_BUBBLE, msg.isUser);

            // Message text
            TextView messageText = new TextView(requireContext());
            messageText.setText(msg.text);
            messageText.setTextSize(15);
            messageText.setTextColor(Color.parseColor(COLOR_TEXT));
            messageText.setLineSpacing(dpToPx(4), 1f);
            bubble.addView(messageText);

            // Timestamp
            TextView timeText = new TextView(requireContext());
            timeText.setText(formatTimestamp(msg.timestamp));
            timeText.setTextSize(10);
            timeText.setTextColor(Color.parseColor(COLOR_MUTED));
            timeText.setPadding(0, dpToPx(4), 0, 0);
            timeText.setGravity(msg.isUser ? Gravity.END : Gravity.START);
            bubble.addView(timeText);

            // Wrap in a FrameLayout to align bubble
            LinearLayout wrapper = new LinearLayout(requireContext());
            wrapper.setLayoutParams(new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT));
            wrapper.setGravity(msg.isUser ? Gravity.END : Gravity.START);
            wrapper.addView(bubble);

            rowContainer.addView(wrapper);
            return rowContainer;
        }
    }

    // ===================== Bubble Background =====================

    private void setBubbleBackground(LinearLayout bubble, String colorHex, boolean isUser) {
        android.graphics.drawable.GradientDrawable drawable = new android.graphics.drawable.GradientDrawable();
        drawable.setColor(Color.parseColor(colorHex));
        if (isUser) {
            // User bubble: rounded top-left, top-right, bottom-left
            drawable.setCornerRadii(new float[]{
                    dpToPx(16), dpToPx(16),
                    dpToPx(16), dpToPx(16),
                    dpToPx(4), dpToPx(4),
                    dpToPx(16), dpToPx(16)
            });
        } else {
            // Agent bubble: rounded top-left, top-right, bottom-right
            drawable.setCornerRadii(new float[]{
                    dpToPx(16), dpToPx(16),
                    dpToPx(16), dpToPx(16),
                    dpToPx(16), dpToPx(16),
                    dpToPx(4), dpToPx(4)
            });
        }
        drawable.setStroke(dpToPx(1), Color.parseColor(isUser ? COLOR_USER_BUBBLE : COLOR_AGENT_ACCENT));
        bubble.setBackground(drawable);
    }

    // ===================== Helpers =====================

    private String formatTimestamp(long millis) {
        java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat("HH:mm", java.util.Locale.getDefault());
        return sdf.format(new java.util.Date(millis));
    }

    private void showConfigDialog() {
        ConfigManager config = ConfigManager.getInstance();
        com.google.gson.JsonObject root = config.getConfig();
        com.google.gson.JsonObject agentConfig = root.has("agent") ? root.getAsJsonObject("agent") : new com.google.gson.JsonObject();

        android.app.AlertDialog.Builder builder = new android.app.AlertDialog.Builder(requireContext());
        builder.setTitle("AI Agent \u914D\u7F6E");

        LinearLayout layout = new LinearLayout(requireContext());
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(dpToPx(20), dpToPx(16), dpToPx(20), dpToPx(16));

        // 端点
        TextView endpointLabel = new TextView(requireContext());
        endpointLabel.setText("API \u7AEF\u70B9");
        endpointLabel.setTextColor(Color.parseColor("#CDD6F4"));
        endpointLabel.setTextSize(14);
        endpointLabel.setPadding(0, 0, 0, 4);
        layout.addView(endpointLabel);

        EditText endpointInput = new EditText(requireContext());
        endpointInput.setHint("https://api.openai.com/v1");
        String ep = agentConfig.has("custom_endpoint") ? agentConfig.get("custom_endpoint").getAsString() : "";
        endpointInput.setText(ep);
        endpointInput.setTextColor(Color.parseColor("#CDD6F4"));
        endpointInput.setHintTextColor(Color.parseColor("#6B7280"));
        endpointInput.setBackgroundColor(Color.parseColor("#313244"));
        endpointInput.setPadding(dpToPx(12), dpToPx(8), dpToPx(12), dpToPx(8));
        layout.addView(endpointInput);

        // API Key
        TextView keyLabel = new TextView(requireContext());
        keyLabel.setText("API Key");
        keyLabel.setTextColor(Color.parseColor("#CDD6F4"));
        keyLabel.setTextSize(14);
        keyLabel.setPadding(0, 0, 0, 4);
        layout.addView(keyLabel);

        EditText keyInput = new EditText(requireContext());
        keyInput.setHint("sk-...");
        String ak = agentConfig.has("custom_api_key") ? agentConfig.get("custom_api_key").getAsString() : "";
        keyInput.setText(ak);
        keyInput.setTextColor(Color.parseColor("#CDD6F4"));
        keyInput.setHintTextColor(Color.parseColor("#6B7280"));
        keyInput.setBackgroundColor(Color.parseColor("#313244"));
        keyInput.setPadding(dpToPx(12), dpToPx(8), dpToPx(12), dpToPx(8));
        layout.addView(keyInput);

        // 模型
        TextView modelLabel = new TextView(requireContext());
        modelLabel.setText("\u6A21\u578B\u540D\u79F0");
        modelLabel.setTextColor(Color.parseColor("#CDD6F4"));
        modelLabel.setTextSize(14);
        modelLabel.setPadding(0, 0, 0, 4);
        layout.addView(modelLabel);

        EditText modelInput = new EditText(requireContext());
        modelInput.setHint("gpt-4, claude-sonnet, gemini-pro...");
        String md = agentConfig.has("custom_model") ? agentConfig.get("custom_model").getAsString() : "";
        modelInput.setText(md);
        modelInput.setTextColor(Color.parseColor("#CDD6F4"));
        modelInput.setHintTextColor(Color.parseColor("#6B7280"));
        modelInput.setBackgroundColor(Color.parseColor("#313244"));
        modelInput.setPadding(dpToPx(12), dpToPx(8), dpToPx(12), dpToPx(8));
        layout.addView(modelInput);

        builder.setView(layout);
        builder.setPositiveButton("\u4FDD\u5B58", new android.content.DialogInterface.OnClickListener() {
            @Override
            public void onClick(android.content.DialogInterface dialog, int which) {
                com.google.gson.JsonObject agent = new com.google.gson.JsonObject();
                agent.addProperty("custom_endpoint", endpointInput.getText().toString().trim());
                agent.addProperty("custom_api_key", keyInput.getText().toString().trim());
                agent.addProperty("custom_model", modelInput.getText().toString().trim());
                root.add("agent", agent);
                config.saveConfig();
                initLLMClient();
                Toast.makeText(requireContext(), "\u914D\u7F6E\u5DF2\u4FDD\u5B58", Toast.LENGTH_SHORT).show();
            }
        });
        builder.setNegativeButton("\u53D6\u6D88", null);
        builder.show();
    }

    private void initLLMClient() {
        ConfigManager config = ConfigManager.getInstance();
        com.google.gson.JsonObject root = config.getConfig();
        if (root.has("agent")) {
            com.google.gson.JsonObject agentConfig = root.getAsJsonObject("agent");
            String endpoint = agentConfig.has("custom_endpoint") ? agentConfig.get("custom_endpoint").getAsString() : "";
            String apiKey = agentConfig.has("custom_api_key") ? agentConfig.get("custom_api_key").getAsString() : "";
            String model = agentConfig.has("custom_model") ? agentConfig.get("custom_model").getAsString() : "";
            if (!endpoint.isEmpty() && !apiKey.isEmpty()) {
                llmClient = new CustomLLMClient(endpoint, apiKey, model);
                Log.i(TAG, "LLM client initialized: " + endpoint + " / " + model);
            }
        }
    }

    private int dpToPx(int dp) {
        float density = getResources().getDisplayMetrics().density;
        return Math.round(dp * density);
    }
}