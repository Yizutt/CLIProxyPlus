package com.cliproxy.plus.agent;

import android.util.Log;

import com.cliproxy.plus.agent.llm.LLMClient;
import com.cliproxy.plus.agent.ToolRegistry;
import com.cliproxy.plus.agent.tools.ToolExecutionResult;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * AIAgentService - AI 智能体核心服务
 * <p>
 * 负责编排完整的对话流程：接收用户输入 → 意图分类 → 工具选择 → 工具执行 → 响应生成。
 * 与 LLMClient 协作完成意图理解和自然语言生成，通过 ToolRegistry 实现工具调度与执行，
 * 并在内存中维护会话状态与历史记录。
 * </p>
 *
 * <p>
 * 使用示例：
 * <pre>
 * AIAgentService agent = AIAgentService.getInstance();
 * JSONObject result = agent.processMessage("帮我查询昨天的流量使用情况", "conv_001");
 * String reply = result.optString("response");
 * </pre>
 * </p>
 *
 * @author CLIProxy Plus
 * @version 1.0
 */
public class AIAgentService {

    private static final String TAG = "AIAgentService";

    /** 单例实例 */
    private static volatile AIAgentService instance;

    /** 大语言模型客户端，用于意图理解和响应生成 */
    private final LLMClient llmClient;

    /** 工具注册表，用于检索和执行可用工具 */
    private final ToolRegistry toolRegistry;

    /** 会话状态存储，conversationId -> ConversationState */
    private final ConcurrentHashMap<String, ConversationState> conversationStore;

    /** 默认系统提示词 */
    private static final String DEFAULT_SYSTEM_PROMPT =
            "你是一个智能助手。请根据用户的问题和上下文，准确理解用户意图，"
                    + "必要时调用可用工具来完成任务，并以自然语言回复用户。";

    // ======================== 单例初始化 ========================

    /**
     * 私有构造方法，初始化 LLM 客户端、工具注册表和会话存储。
     */
    private AIAgentService() {
        this.llmClient = new LLMClient();
        this.toolRegistry = new ToolRegistry();
        this.conversationStore = new ConcurrentHashMap<>();
        Log.i(TAG, "AIAgentService 初始化完成");
    }

    /**
     * 获取 AIAgentService 单例实例。
     *
     * @return AIAgentService 实例
     */
    public static AIAgentService getInstance() {
        if (instance == null) {
            synchronized (AIAgentService.class) {
                if (instance == null) {
                    instance = new AIAgentService();
                }
            }
        }
        return instance;
    }

    /**
     * 重置单例实例（仅用于测试或全局重置场景）。
     */
    public static synchronized void resetInstance() {
        if (instance != null) {
            instance.conversationStore.clear();
            instance = null;
            Log.w(TAG, "AIAgentService 实例已重置");
        }
    }

    // ======================== 核心流程编排 ========================

    /**
     * 处理用户消息，执行完整的对话流程：
     * <ol>
     *   <li>获取或创建会话上下文</li>
     *   <li>将用户消息追加到历史记录</li>
     *   <li>调用 LLM 进行意图分类</li>
     *   <li>根据意图选择并执行工具（如有需要）</li>
     *   <li>将工具执行结果注入上下文</li>
     *   <li>调用 LLM 生成最终回复</li>
     *   <li>将助手回复追加到历史记录</li>
     *   <li>返回结构化结果</li>
     * </ol>
     *
     * @param userMessage    用户输入的消息文本
     * @param conversationId 会话标识符，为 null 或空时自动生成新 ID
     * @return JSONObject，包含以下字段：
     *         <ul>
     *           <li>"response" - 助手生成的回复文本</li>
     *           <li>"conversationId" - 会话 ID</li>
     *           <li>"intent" - 识别到的意图分类（可选）</li>
     *           <li>"toolUsed" - 使用的工具名称（可选）</li>
     *           <li>"error" - 错误信息（处理失败时存在）</li>
     *         </ul>
     */
    public JSONObject processMessage(String userMessage, String conversationId) {
        long startTime = System.currentTimeMillis();

        // 参数校验
        if (userMessage == null || userMessage.trim().isEmpty()) {
            return createErrorResponse("用户消息不能为空");
        }

        // 步骤 1：获取或创建会话上下文
        String effectiveConversationId = (conversationId == null || conversationId.trim().isEmpty())
                ? generateConversationId() : conversationId;
        ConversationState conversation = getOrCreateConversation(effectiveConversationId);
        Log.d(TAG, "处理消息 - 会话: " + effectiveConversationId + ", 消息: " + truncateMessage(userMessage));

        try {
            // 步骤 2：追加用户消息
            appendUserMessage(conversation, userMessage);

            // 步骤 3：意图分类
            IntentClassification intent = classifyIntent(conversation, userMessage);
            Log.d(TAG, "意图分类结果: " + intent.getIntentName());

            String toolUsed = null;
            String toolResult = null;

            // 步骤 4：根据意图选择并执行工具
            if (intent.requiresTool()) {
                String selectedTool = selectTool(intent, conversation);
                if (selectedTool != null) {
                    toolUsed = selectedTool;
                    Log.d(TAG, "选择工具: " + selectedTool);

                    // 步骤 5：执行工具并获取结果
                    ToolExecutionResult executionResult = executeTool(selectedTool, intent, conversation);
                    toolResult = executionResult.getResult();
                    conversation.setLastToolResult(toolResult);
                    Log.d(TAG, "工具执行完成: " + selectedTool
                            + ", 成功: " + executionResult.isSuccess());
                }
            }

            // 步骤 6：生成最终回复
            String response = generateResponse(conversation, intent, toolResult);

            // 步骤 7：追加助手回复
            appendAssistantMessage(conversation, response);

            long elapsed = System.currentTimeMillis() - startTime;
            Log.i(TAG, "消息处理完成 - 会话: " + effectiveConversationId
                    + ", 耗时: " + elapsed + "ms");

            // 步骤 8：返回结构化结果
            JSONObject result = new JSONObject();
            result.put("response", response);
            result.put("conversationId", effectiveConversationId);
            result.put("intent", intent.getIntentName());
            if (toolUsed != null) {
                result.put("toolUsed", toolUsed);
            }
            return result;

        } catch (Exception e) {
            Log.e(TAG, "处理消息时发生异常", e);
            return createErrorResponse("处理消息时发生错误: " + e.getMessage());
        }
    }

    /**
     * 获取指定会话的完整历史记录。
     *
     * @param conversationId 会话标识符
     * @return JSONArray，包含会话中的所有消息记录；
     *         若会话不存在则返回空数组
     */
    public JSONArray getConversationHistory(String conversationId) {
        if (conversationId == null || conversationId.trim().isEmpty()) {
            Log.w(TAG, "获取历史记录失败: conversationId 为空");
            return new JSONArray();
        }

        ConversationState conversation = conversationStore.get(conversationId);
        if (conversation == null) {
            Log.w(TAG, "会话不存在: " + conversationId);
            return new JSONArray();
        }

        JSONArray history = new JSONArray();
        for (ConversationMessage msg : conversation.getMessages()) {
            history.put(msg.toJson());
        }
        Log.d(TAG, "获取会话历史 - 会话: " + conversationId
                + ", 消息数: " + history.length());
        return history;
    }

    /**
     * 清除指定会话的所有状态和历史记录。
     *
     * @param conversationId 会话标识符
     * @return true 表示成功清除，false 表示会话不存在
     */
    public boolean clearConversation(String conversationId) {
        if (conversationId == null || conversationId.trim().isEmpty()) {
            Log.w(TAG, "清除会话失败: conversationId 为空");
            return false;
        }

        ConversationState removed = conversationStore.remove(conversationId);
        if (removed != null) {
            Log.i(TAG, "会话已清除: " + conversationId);
            return true;
        } else {
            Log.w(TAG, "清除会话失败 - 会话不存在: " + conversationId);
            return false;
        }
    }

    // ======================== 流程子步骤 ========================

    /**
     * 意图分类 - 调用 LLM 分析用户消息的意图。
     *
     * @param conversation 当前会话状态
     * @param userMessage  用户消息
     * @return 意图分类结果
     */
    private IntentClassification classifyIntent(ConversationState conversation, String userMessage) {
        Log.d(TAG, "开始意图分类");

        // 构建意图分类提示
        String classificationPrompt = buildClassificationPrompt(userMessage, conversation);

        // 调用 LLM 获取意图
        String llmResponse = llmClient.chat(conversation.getSystemPrompt(), classificationPrompt);
        return IntentClassification.parse(llmResponse);
    }

    /**
     * 工具选择 - 根据意图从 ToolRegistry 选择最合适的工具。
     *
     * @param intent       意图分类结果
     * @param conversation 当前会话状态
     * @return 工具名称，若无需工具则返回 null
     */
    private String selectTool(IntentClassification intent, ConversationState conversation) {
        if (!intent.requiresTool()) {
            return null;
        }

        // 查询可用工具列表
        List<String> availableTools = toolRegistry.getAvailableTools();
        if (availableTools.isEmpty()) {
            Log.w(TAG, "无可用工具可执行");
            return null;
        }

        // 让 LLM 基于意图和工具列表选择最合适的工具
        String selectionPrompt = buildToolSelectionPrompt(intent, availableTools, conversation);
        String selectedTool = llmClient.chat(conversation.getSystemPrompt(), selectionPrompt);

        // 验证选择的工具是否在可用列表中
        if (selectedTool != null && availableTools.contains(selectedTool)) {
            return selectedTool;
        }

        Log.w(TAG, "LLM 选择的工具不可用: " + selectedTool);
        return null;
    }

    /**
     * 工具执行 - 调用 ToolRegistry 执行指定工具。
     *
     * @param toolName     工具名称
     * @param intent       意图分类结果
     * @param conversation 当前会话状态
     * @return 工具执行结果
     */
    private ToolExecutionResult executeTool(String toolName, IntentClassification intent,
                                            ConversationState conversation) {
        Log.d(TAG, "执行工具: " + toolName);

        // 从意图中提取工具参数
        JSONObject toolParams = intent.getToolParameters();
        Log.d(TAG, "工具参数: " + (toolParams != null ? toolParams.toString() : "无"));

        // 执行工具
        return toolRegistry.execute(toolName, toolParams, conversation);
    }

    /**
     * 响应生成 - 调用 LLM 生成最终的自然语言回复。
     *
     * @param conversation 当前会话状态
     * @param intent       意图分类结果
     * @param toolResult   工具执行结果（可能为 null）
     * @return 生成的回复文本
     */
    private String generateResponse(ConversationState conversation, IntentClassification intent,
                                    String toolResult) {
        Log.d(TAG, "开始生成响应");

        // 构建生成提示，包含工具执行结果（如有）
        String generationPrompt = buildResponsePrompt(intent, toolResult, conversation);
        return llmClient.chat(conversation.getSystemPrompt(), generationPrompt);
    }

    // ======================== 提示构建 ========================

    /**
     * 构建意图分类提示词。
     */
    private String buildClassificationPrompt(String userMessage, ConversationState conversation) {
        StringBuilder sb = new StringBuilder();
        sb.append("【任务】分析用户消息的意图，判断是否需要调用工具。\n\n");
        sb.append("可用工具列表：\n");

        List<String> tools = toolRegistry.getAvailableTools();
        if (tools.isEmpty()) {
            sb.append("  - 当前无可用工具\n");
        } else {
            for (String tool : tools) {
                sb.append("  - ").append(tool).append("\n");
            }
        }

        sb.append("\n【用户消息】\n").append(userMessage).append("\n\n");
        sb.append("请以 JSON 格式返回，格式：\n");
        sb.append("{\"intent\": \"意图名称\", \"requiresTool\": true/false, ");
        sb.append("\"toolName\": \"工具名称或null\", \"toolParameters\": {}}\n");
        return sb.toString();
    }

    /**
     * 构建工具选择提示词。
     */
    private String buildToolSelectionPrompt(IntentClassification intent,
                                            List<String> availableTools, ConversationState conversation) {
        StringBuilder sb = new StringBuilder();
        sb.append("【任务】根据用户意图，从以下工具中选择最合适的一个。\n\n");
        sb.append("用户意图：").append(intent.getIntentName()).append("\n\n");
        sb.append("可用工具：\n");
        for (String tool : availableTools) {
            sb.append("  - ").append(tool).append("\n");
        }
        sb.append("\n请直接返回工具名称，无需其他内容。");
        return sb.toString();
    }

    /**
     * 构建响应生成提示词。
     */
    private String buildResponsePrompt(IntentClassification intent, String toolResult,
                                       ConversationState conversation) {
        StringBuilder sb = new StringBuilder();
        sb.append("请根据以下信息生成回复。\n\n");
        sb.append("用户意图：").append(intent.getIntentName()).append("\n");

        if (toolResult != null) {
            sb.append("工具执行结果：\n").append(toolResult).append("\n");
        }

        sb.append("\n请以自然语言回复用户，准确传达信息。");

        // 如果有最近的对话历史，加入上下文
        List<ConversationMessage> recentMessages = conversation.getRecentMessages(5);
        if (!recentMessages.isEmpty()) {
            sb.append("\n\n最近对话上下文：\n");
            for (ConversationMessage msg : recentMessages) {
                sb.append(msg.getRole()).append(": ").append(msg.getContent()).append("\n");
            }
        }

        return sb.toString();
    }

    // ======================== 会话管理 ========================

    /**
     * 获取或创建会话状态。
     */
    private ConversationState getOrCreateConversation(String conversationId) {
        return conversationStore.computeIfAbsent(conversationId, id -> {
            Log.i(TAG, "创建新会话: " + id);
            return new ConversationState(id, DEFAULT_SYSTEM_PROMPT);
        });
    }

    /**
     * 将用户消息追加到会话历史。
     */
    private void appendUserMessage(ConversationState conversation, String message) {
        ConversationMessage msg = new ConversationMessage("user", message);
        conversation.addMessage(msg);
    }

    /**
     * 将助手回复追加到会话历史。
     */
    private void appendAssistantMessage(ConversationState conversation, String message) {
        ConversationMessage msg = new ConversationMessage("assistant", message);
        conversation.addMessage(msg);
    }

    /**
     * 生成唯一会话 ID。
     */
    private String generateConversationId() {
        return "conv_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
    }

    /**
     * 截断消息用于日志显示。
     */
    private String truncateMessage(String message) {
        if (message == null) return "null";
        return message.length() > 50 ? message.substring(0, 50) + "..." : message;
    }

    /**
     * 创建错误响应 JSON。
     */
    private JSONObject createErrorResponse(String errorMessage) {
        JSONObject error = new JSONObject();
        try {
            error.put("error", errorMessage);
            error.put("conversationId", "");
        } catch (Exception e) {
            Log.e(TAG, "创建错误响应时发生异常", e);
        }
        return error;
    }

    // ======================== 辅助方法 ========================

    /**
     * 获取当前活跃会话数量。
     *
     * @return 活跃会话数
     */
    public int getActiveConversationCount() {
        return conversationStore.size();
    }

    /**
     * 获取指定会话的最后 N 条消息（只读）。
     *
     * @param conversationId 会话标识符
     * @param count          消息条数
     * @return 不可修改的消息列表，会话不存在时返回空列表
     */
    public List<ConversationMessage> getRecentMessages(String conversationId, int count) {
        ConversationState conversation = conversationStore.get(conversationId);
        if (conversation == null) {
            return Collections.emptyList();
        }
        return Collections.unmodifiableList(conversation.getRecentMessages(count));
    }

    /**
     * 获取 LLM 客户端实例（供外部高级定制使用）。
     *
     * @return LLMClient 实例
     */
    public LLMClient getLlmClient() {
        return llmClient;
    }

    /**
     * 获取工具注册表实例（供外部动态注册/注销工具使用）。
     *
     * @return ToolRegistry 实例
     */
    public ToolRegistry getToolRegistry() {
        return toolRegistry;
    }

    // ======================== 内部数据结构 ========================

    /**
     * ConversationState - 会话状态
     * <p>
     * 维护单个会话的上下文信息，包括系统提示词、消息历史、最近工具执行结果等。
     * </p>
     */
    public static class ConversationState {

        private final String conversationId;
        private final String systemPrompt;
        private final List<ConversationMessage> messages;
        private String lastToolResult;
        private long createdAt;
        private long lastUpdatedAt;

        /**
         * 构造会话状态实例。
         *
         * @param conversationId 会话 ID
         * @param systemPrompt   系统提示词
         */
        public ConversationState(String conversationId, String systemPrompt) {
            this.conversationId = conversationId;
            this.systemPrompt = systemPrompt;
            this.messages = new ArrayList<>();
            this.lastToolResult = null;
            long now = System.currentTimeMillis();
            this.createdAt = now;
            this.lastUpdatedAt = now;
        }

        /**
         * 添加消息到历史记录。
         *
         * @param message 消息对象
         */
        public void addMessage(ConversationMessage message) {
            messages.add(message);
            this.lastUpdatedAt = System.currentTimeMillis();
        }

        /**
         * 获取会话 ID。
         *
         * @return 会话 ID
         */
        public String getConversationId() {
            return conversationId;
        }

        /**
         * 获取系统提示词。
         *
         * @return 系统提示词
         */
        public String getSystemPrompt() {
            return systemPrompt;
        }

        /**
         * 获取全部消息列表。
         *
         * @return 消息列表
         */
        public List<ConversationMessage> getMessages() {
            return messages;
        }

        /**
         * 获取最近 N 条消息。
         *
         * @param n 消息条数
         * @return 最近 N 条消息的子列表
         */
        public List<ConversationMessage> getRecentMessages(int n) {
            if (n <= 0 || messages.isEmpty()) {
                return new ArrayList<>();
            }
            int fromIndex = Math.max(0, messages.size() - n);
            return new ArrayList<>(messages.subList(fromIndex, messages.size()));
        }

        /**
         * 获取最后工具执行结果。
         */
        public String getLastToolResult() {
            return lastToolResult;
        }

        /**
         * 设置最后工具执行结果。
         */
        public void setLastToolResult(String lastToolResult) {
            this.lastToolResult = lastToolResult;
            this.lastUpdatedAt = System.currentTimeMillis();
        }

        /**
         * 获取会话创建时间戳。
         */
        public long getCreatedAt() {
            return createdAt;
        }

        /**
         * 获取最后更新时间戳。
         */
        public long getLastUpdatedAt() {
            return lastUpdatedAt;
        }

        /**
         * 获取消息数量。
         */
        public int getMessageCount() {
            return messages.size();
        }

        /**
         * 将会话状态导出为 JSON 对象。
         *
         * @return JSONObject 格式的会话摘要
         */
        public JSONObject toJson() {
            JSONObject json = new JSONObject();
            try {
                json.put("conversationId", conversationId);
                json.put("messageCount", messages.size());
                json.put("createdAt", createdAt);
                json.put("lastUpdatedAt", lastUpdatedAt);
                json.put("hasToolResult", lastToolResult != null);
            } catch (Exception e) {
                Log.e(TAG, "会话状态序列化失败", e);
            }
            return json;
        }
    }

    /**
     * ConversationMessage - 会话消息
     * <p>
     * 表示一条对话消息，包含角色（user/assistant/system）和内容。
     * </p>
     */
    public static class ConversationMessage {

        private final String role;
        private final String content;
        private final long timestamp;

        /**
         * 构造消息实例。
         *
         * @param role    消息角色（user / assistant / system）
         * @param content 消息内容
         */
        public ConversationMessage(String role, String content) {
            this.role = role;
            this.content = content;
            this.timestamp = System.currentTimeMillis();
        }

        /**
         * 获取消息角色。
         *
         * @return 角色名称
         */
        public String getRole() {
            return role;
        }

        /**
         * 获取消息内容。
         *
         * @return 消息文本
         */
        public String getContent() {
            return content;
        }

        /**
         * 获取消息时间戳。
         *
         * @return 时间戳（毫秒）
         */
        public long getTimestamp() {
            return timestamp;
        }

        /**
         * 转换为 JSONObject 格式。
         *
         * @return JSONObject 表示
         */
        public JSONObject toJson() {
            JSONObject json = new JSONObject();
            try {
                json.put("role", role);
                json.put("content", content);
                json.put("timestamp", timestamp);
            } catch (Exception e) {
                Log.e(TAG, "消息序列化失败", e);
            }
            return json;
        }
    }

    /**
     * IntentClassification - 意图分类结果
     * <p>
     * 封装 LLM 意图分类的返回结果，包括意图名称、是否需要工具、工具参数等。
     * </p>
     */
    public static class IntentClassification {

        private final String intentName;
        private final boolean requiresTool;
        private final String selectedToolName;
        private final JSONObject toolParameters;

        /**
         * 构造意图分类结果。
         *
         * @param intentName      意图名称
         * @param requiresTool    是否需要工具调用
         * @param selectedToolName 选定的工具名称（可为 null）
         * @param toolParameters  工具参数 JSON（可为 null）
         */
        public IntentClassification(String intentName, boolean requiresTool,
                                     String selectedToolName, JSONObject toolParameters) {
            this.intentName = intentName;
            this.requiresTool = requiresTool;
            this.selectedToolName = selectedToolName;
            this.toolParameters = toolParameters;
        }

        /**
         * 从 LLM 返回的 JSON 字符串解析意图分类结果。
         *
         * @param llmResponse LLM 返回的 JSON 字符串
         * @return 解析后的 IntentClassification 实例
         */
        public static IntentClassification parse(String llmResponse) {
            if (llmResponse == null || llmResponse.trim().isEmpty()) {
                return new IntentClassification("unknown", false, null, null);
            }

            try {
                // 尝试从返回内容中提取 JSON 部分
                String jsonStr = extractJson(llmResponse);
                JSONObject json = new JSONObject(jsonStr);

                String intent = json.optString("intent", "general_chat");
                boolean requiresTool = json.optBoolean("requiresTool", false);
                String toolName = json.optString("toolName", null);
                JSONObject params = json.optJSONObject("toolParameters");

                // 空字符串视为 null
                if (toolName != null && toolName.trim().isEmpty()) {
                    toolName = null;
                }

                return new IntentClassification(intent, requiresTool, toolName, params);

            } catch (Exception e) {
                Log.w(TAG, "意图分类 JSON 解析失败，使用默认值", e);
                return new IntentClassification("general_chat", false, null, null);
            }
        }

        /**
         * 从文本中提取 JSON 对象（包容前后缀文本）。
         */
        private static String extractJson(String text) {
            int start = text.indexOf('{');
            int end = text.lastIndexOf('}');
            if (start != -1 && end != -1 && end > start) {
                return text.substring(start, end + 1);
            }
            return text;
        }

        /**
         * 获取意图名称。
         */
        public String getIntentName() {
            return intentName;
        }

        /**
         * 判断是否需要执行工具。
         */
        public boolean requiresTool() {
            return requiresTool;
        }

        /**
         * 获取选定工具名称。
         */
        public String getSelectedToolName() {
            return selectedToolName;
        }

        /**
         * 获取工具参数。
         */
        public JSONObject getToolParameters() {
            return toolParameters != null ? toolParameters : new JSONObject();
        }

        @Override
        public String toString() {
            return "IntentClassification{intent='" + intentName + "', requiresTool="
                    + requiresTool + ", tool='" + selectedToolName + "'}";
        }
    }
}