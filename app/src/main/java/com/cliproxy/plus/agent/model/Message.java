package com.cliproxy.plus.agent.model;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Message - 对话消息数据模型
 * <p>
 * 表示一条对话中的单条消息，支持用户、助手、系统和工具四种角色。
 * 当 role 为 "tool" 时，通过 toolCallId、toolName、toolParams、toolResult
 * 描述工具调用的请求与响应。toolCalls 字段用于存储助手消息中的工具调用列表。
 * </p>
 */
public class Message {

    private static final String TAG = "Message";

    /** 消息唯一标识 */
    private final String id;

    /** 消息角色：user（用户）、assistant（助手）、system（系统）、tool（工具） */
    private final String role;

    /** 消息文本内容 */
    private final String content;

    /** 消息时间戳（毫秒） */
    private final long timestamp;

    /** 工具调用列表，仅 role 为 assistant 时使用，每个元素为 JSONObject 格式 */
    private final List<JSONObject> toolCalls;

    /** 工具调用 ID，仅 role 为 tool 时使用 */
    private final String toolCallId;

    /** 工具名称，仅 role 为 tool 时使用 */
    private final String toolName;

    /** 工具调用参数，仅 role 为 tool 时使用 */
    private final JSONObject toolParams;

    /** 工具调用结果，仅 role 为 tool 时使用 */
    private final JSONObject toolResult;

    /**
     * 构造一条完整的消息
     *
     * @param id         消息唯一标识
     * @param role       消息角色（user/assistant/system/tool）
     * @param content    消息文本内容
     * @param timestamp  消息时间戳（毫秒）
     * @param toolCalls  工具调用列表（assistant 角色使用）
     * @param toolCallId 工具调用 ID（tool 角色使用）
     * @param toolName   工具名称（tool 角色使用）
     * @param toolParams 工具调用参数（tool 角色使用）
     * @param toolResult 工具调用结果（tool 角色使用）
     */
    public Message(String id, String role, String content, long timestamp,
                   List<JSONObject> toolCalls, String toolCallId, String toolName,
                   JSONObject toolParams, JSONObject toolResult) {
        this.id = id != null ? id : "";
        this.role = role != null ? role : "user";
        this.content = content != null ? content : "";
        this.timestamp = timestamp > 0 ? timestamp : System.currentTimeMillis();
        this.toolCalls = toolCalls != null ? new ArrayList<>(toolCalls) : new ArrayList<JSONObject>();
        this.toolCallId = toolCallId != null ? toolCallId : "";
        this.toolName = toolName != null ? toolName : "";
        this.toolParams = toolParams != null ? toolParams : new JSONObject();
        this.toolResult = toolResult != null ? toolResult : new JSONObject();
    }

    /**
     * 构造一条普通消息（无工具调用相关字段）
     *
     * @param id        消息唯一标识
     * @param role      消息角色（user/assistant/system）
     * @param content   消息文本内容
     * @param timestamp 消息时间戳（毫秒）
     */
    public Message(String id, String role, String content, long timestamp) {
        this(id, role, content, timestamp, null, null, null, null, null);
    }

    /**
     * 构造一条简单的用户消息，自动生成 ID 和时间戳
     *
     * @param content 消息文本内容
     * @return 用户消息实例
     */
    public static Message createUserMessage(String content) {
        return new Message(java.util.UUID.randomUUID().toString(),
                "user", content, System.currentTimeMillis());
    }

    /**
     * 构造一条简单的助手消息，自动生成 ID 和时间戳
     *
     * @param content 消息文本内容
     * @return 助手消息实例
     */
    public static Message createAssistantMessage(String content) {
        return new Message(java.util.UUID.randomUUID().toString(),
                "assistant", content, System.currentTimeMillis());
    }

    /**
     * 构造一条系统消息，自动生成 ID 和时间戳
     *
     * @param content 消息文本内容
     * @return 系统消息实例
     */
    public static Message createSystemMessage(String content) {
        return new Message(java.util.UUID.randomUUID().toString(),
                "system", content, System.currentTimeMillis());
    }

    /**
     * 构造一条工具消息，自动生成 ID 和时间戳
     *
     * @param toolCallId 工具调用 ID
     * @param toolName   工具名称
     * @param toolParams 工具调用参数
     * @param toolResult 工具调用结果
     * @return 工具消息实例
     */
    public static Message createToolMessage(String toolCallId, String toolName,
                                            JSONObject toolParams, JSONObject toolResult) {
        return new Message(java.util.UUID.randomUUID().toString(),
                "tool", "", System.currentTimeMillis(),
                null, toolCallId, toolName, toolParams, toolResult);
    }

    /**
     * 获取消息唯一标识
     *
     * @return 消息 ID
     */
    public String getId() {
        return id;
    }

    /**
     * 获取消息角色
     *
     * @return 角色（user/assistant/system/tool）
     */
    public String getRole() {
        return role;
    }

    /**
     * 获取消息文本内容
     *
     * @return 消息内容
     */
    public String getContent() {
        return content;
    }

    /**
     * 获取消息时间戳（毫秒）
     *
     * @return 时间戳
     */
    public long getTimestamp() {
        return timestamp;
    }

    /**
     * 获取工具调用列表
     *
     * @return 不可修改的工具调用列表，仅 assistant 角色时有值
     */
    public List<JSONObject> getToolCalls() {
        return Collections.unmodifiableList(toolCalls);
    }

    /**
     * 获取工具调用 ID
     *
     * @return 工具调用 ID，仅 tool 角色时有值
     */
    public String getToolCallId() {
        return toolCallId;
    }

    /**
     * 获取工具名称
     *
     * @return 工具名称，仅 tool 角色时有值
     */
    public String getToolName() {
        return toolName;
    }

    /**
     * 获取工具调用参数
     *
     * @return 调用参数 JSON，仅 tool 角色时有值
     */
    public JSONObject getToolParams() {
        return toolParams;
    }

    /**
     * 获取工具调用结果
     *
     * @return 调用结果 JSON，仅 tool 角色时有值
     */
    public JSONObject getToolResult() {
        return toolResult;
    }

    /**
     * 判断当前消息是否为用户消息
     *
     * @return true 表示用户消息
     */
    public boolean isUser() {
        return "user".equals(role);
    }

    /**
     * 判断当前消息是否为助手消息
     *
     * @return true 表示助手消息
     */
    public boolean isAssistant() {
        return "assistant".equals(role);
    }

    /**
     * 判断当前消息是否为系统消息
     *
     * @return true 表示系统消息
     */
    public boolean isSystem() {
        return "system".equals(role);
    }

    /**
     * 判断当前消息是否为工具消息
     *
     * @return true 表示工具消息
     */
    public boolean isTool() {
        return "tool".equals(role);
    }

    /**
     * 判断该消息是否包含工具调用（仅 assistant 角色且 toolCalls 非空）
     *
     * @return true 表示包含工具调用
     */
    public boolean hasToolCalls() {
        return !toolCalls.isEmpty();
    }

    /**
     * 获取工具调用数量
     *
     * @return 工具调用个数
     */
    public int getToolCallCount() {
        return toolCalls.size();
    }

    /**
     * 将当前消息序列化为 JSONObject
     * <p>
     * 输出格式：
     * <pre>
     * {
     *   "id": "...",
     *   "role": "user|assistant|system|tool",
     *   "content": "...",
     *   "timestamp": 1234567890,
     *   "toolCalls": [ ... ],
     *   "toolCallId": "...",
     *   "toolName": "...",
     *   "toolParams": { ... },
     *   "toolResult": { ... }
     * }
     * </pre>
     *
     * @return 表示该消息的 JSONObject
     */
    public JSONObject toJson() {
        try {
            JSONObject json = new JSONObject();
            json.put("id", id);
            json.put("role", role);
            json.put("content", content);
            json.put("timestamp", timestamp);

            if (!toolCalls.isEmpty()) {
                json.put("toolCalls", new JSONArray(toolCalls));
            }

            if (!toolCallId.isEmpty()) {
                json.put("toolCallId", toolCallId);
            }
            if (!toolName.isEmpty()) {
                json.put("toolName", toolName);
            }
            if (toolParams.length() > 0) {
                json.put("toolParams", toolParams);
            }
            if (toolResult.length() > 0) {
                json.put("toolResult", toolResult);
            }

            return json;
        } catch (Exception e) {
            Log.e(TAG, "序列化消息 JSON 失败: " + e.getMessage(), e);
            return new JSONObject();
        }
    }

    /**
     * 从 JSONObject 反序列化消息
     *
     * @param json 包含消息字段的 JSONObject
     * @return 解析得到的 Message 实例，解析失败时返回 null
     */
    public static Message fromJson(JSONObject json) {
        try {
            String id = json.optString("id", "");
            String role = json.optString("role", "user");
            String content = json.optString("content", "");
            long timestamp = json.optLong("timestamp", System.currentTimeMillis());

            // 解析 toolCalls（可选）
            List<JSONObject> toolCalls = new ArrayList<JSONObject>();
            JSONArray toolCallsArray = json.optJSONArray("toolCalls");
            if (toolCallsArray != null) {
                for (int i = 0; i < toolCallsArray.length(); i++) {
                    JSONObject tc = toolCallsArray.optJSONObject(i);
                    if (tc != null) {
                        toolCalls.add(tc);
                    }
                }
            }

            String toolCallId = json.optString("toolCallId", "");
            String toolName = json.optString("toolName", "");
            JSONObject toolParams = json.optJSONObject("toolParams");
            JSONObject toolResult = json.optJSONObject("toolResult");

            if (id.isEmpty()) {
                Log.w(TAG, "反序列化失败：消息 ID 为空");
                return null;
            }

            return new Message(id, role, content, timestamp,
                    toolCalls, toolCallId, toolName, toolParams, toolResult);
        } catch (Exception e) {
            Log.e(TAG, "反序列化消息失败: " + e.getMessage(), e);
            return null;
        }
    }

    /**
     * 从 JSONArray 反序列化多条消息
     *
     * @param jsonArray 包含多条消息的 JSONArray
     * @return 消息列表，解析失败时返回空列表
     */
    public static List<Message> fromJsonArray(JSONArray jsonArray) {
        List<Message> messages = new ArrayList<Message>();
        if (jsonArray == null) {
            return messages;
        }
        for (int i = 0; i < jsonArray.length(); i++) {
            JSONObject obj = jsonArray.optJSONObject(i);
            if (obj != null) {
                Message message = fromJson(obj);
                if (message != null) {
                    messages.add(message);
                }
            }
        }
        return messages;
    }

    /**
     * 将消息列表序列化为 JSONArray
     *
     * @param messages 消息列表
     * @return 序列化后的 JSONArray
     */
    public static JSONArray toJsonArray(List<Message> messages) {
        JSONArray array = new JSONArray();
        if (messages == null) {
            return array;
        }
        for (Message message : messages) {
            array.put(message.toJson());
        }
        return array;
    }

    @Override
    public String toString() {
        return "Message{"
                + "id='" + id + '\''
                + ", role='" + role + '\''
                + ", content='" + (content.length() > 50
                        ? content.substring(0, 50) + "..."
                        : content)
                + '\''
                + ", timestamp=" + timestamp
                + ", toolCalls=" + toolCalls.size()
                + ", toolCallId='" + toolCallId + '\''
                + ", toolName='" + toolName + '\''
                + '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Message message = (Message) o;
        return id.equals(message.id);
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }
}