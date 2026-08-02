package com.cliproxy.plus.agent.model;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Conversation - AI Agent 对话数据模型
 * <p>
 * 表示一次与 AI 智能体的完整对话，包含对话的唯一标识、标题、消息列表、
 * 创建/更新时间戳以及附加元数据。提供消息增删查改、清空等基础操作，
 * 并支持序列化为 JSON 格式以便持久化存储或网络传输。
 * </p>
 */
public class Conversation {

    private static final String TAG = "Conversation";

    /** 对话唯一标识 */
    private final String id;

    /** 对话标题 */
    private String title;

    /** 对话创建时间戳（毫秒） */
    private long createdAt;

    /** 对话最后更新时间戳（毫秒） */
    private long updatedAt;

    /** 对话中的消息列表 */
    private final List<Message> messages;

    /** 对话附加元数据 */
    private final Map<String, Object> metadata;

    /**
     * 构造一个完整的对话实例
     *
     * @param id        对话唯一标识
     * @param title     对话标题
     * @param createdAt 创建时间戳（毫秒）
     * @param updatedAt 最后更新时间戳（毫秒）
     * @param messages  消息列表
     * @param metadata  附加元数据
     */
    public Conversation(String id, String title, long createdAt, long updatedAt,
                        List<Message> messages, Map<String, Object> metadata) {
        this.id = id != null ? id : "";
        this.title = title != null ? title : "";
        this.createdAt = createdAt > 0 ? createdAt : System.currentTimeMillis();
        this.updatedAt = updatedAt > 0 ? updatedAt : this.createdAt;
        this.messages = messages != null ? new ArrayList<Message>(messages) : new ArrayList<Message>();
        this.metadata = metadata != null ? new HashMap<String, Object>(metadata) : new HashMap<String, Object>();
    }

    /**
     * 构造一个空对话，自动生成 ID 并设置创建时间
     *
     * @param title 对话标题
     */
    public Conversation(String title) {
        this(UUID.randomUUID().toString(), title, System.currentTimeMillis(),
                System.currentTimeMillis(), new ArrayList<Message>(), new HashMap<String, Object>());
    }

    /**
     * 构造一个仅含 ID 的默认对话实例
     */
    public Conversation() {
        this(UUID.randomUUID().toString(), "", System.currentTimeMillis(),
                System.currentTimeMillis(), new ArrayList<Message>(), new HashMap<String, Object>());
    }

    /**
     * 获取对话唯一标识
     *
     * @return 对话 ID
     */
    public String getId() {
        return id;
    }

    /**
     * 获取对话标题
     *
     * @return 对话标题
     */
    public String getTitle() {
        return title;
    }

    /**
     * 设置对话标题
     *
     * @param title 新的对话标题
     */
    public void setTitle(String title) {
        this.title = title != null ? title : "";
        touch();
    }

    /**
     * 获取对话创建时间戳（毫秒）
     *
     * @return 创建时间戳
     */
    public long getCreatedAt() {
        return createdAt;
    }

    /**
     * 获取对话最后更新时间戳（毫秒）
     *
     * @return 最后更新时间戳
     */
    public long getUpdatedAt() {
        return updatedAt;
    }

    /**
     * 获取对话中的消息列表（不可修改视图）
     *
     * @return 不可修改的消息列表
     */
    public List<Message> getMessages() {
        return Collections.unmodifiableList(messages);
    }

    /**
     * 获取对话附加元数据
     *
     * @return 元数据 Map（修改会反映到原始数据）
     */
    public Map<String, Object> getMetadata() {
        return metadata;
    }

    /**
     * 向对话中添加一条消息
     * <p>
     * 消息将被追加到消息列表末尾，并自动更新对话的最后更新时间戳。
     * </p>
     *
     * @param msg 要添加的消息对象
     */
    public void addMessage(Message msg) {
        if (msg == null) {
            Log.w(TAG, "addMessage 忽略空消息");
            return;
        }
        messages.add(msg);
        touch();
    }

    /**
     * 获取对话中的最后一条消息
     *
     * @return 最后一条消息，如果对话为空则返回 null
     */
    public Message getLastMessage() {
        if (messages.isEmpty()) {
            return null;
        }
        return messages.get(messages.size() - 1);
    }

    /**
     * 获取对话中的消息总数
     *
     * @return 消息数量
     */
    public int getMessageCount() {
        return messages.size();
    }

    /**
     * 清空对话中的所有消息和元数据，重置更新时间为当前时间
     */
    public void clear() {
        messages.clear();
        metadata.clear();
        touch();
    }

    /**
     * 更新对话的最后更新时间戳为当前时间
     * <p>
     * 每次对对话内容进行修改的操作（如添加消息、设置标题、清空等）
     * 会自动调用此方法以保持 updatedAt 字段同步。
     * </p>
     */
    private void touch() {
        this.updatedAt = System.currentTimeMillis();
    }

    /**
     * 将当前对话序列化为 JSONObject
     * <p>
     * 输出格式：
     * <pre>
     * {
     *   "id": "...",
     *   "title": "...",
     *   "createdAt": 1234567890,
     *   "updatedAt": 1234567890,
     *   "messages": [ ... ],
     *   "metadata": { ... }
     * }
     * </pre>
     *
     * @return 表示该对话的 JSONObject
     */
    public JSONObject toJson() {
        try {
            JSONObject json = new JSONObject();
            json.put("id", id);
            json.put("title", title);
            json.put("createdAt", createdAt);
            json.put("updatedAt", updatedAt);
            json.put("messages", Message.toJsonArray(messages));

            // 序列化元数据为 JSONObject
            JSONObject metaJson = new JSONObject();
            for (Map.Entry<String, Object> entry : metadata.entrySet()) {
                String key = entry.getKey();
                Object value = entry.getValue();
                if (value instanceof String) {
                    metaJson.put(key, (String) value);
                } else if (value instanceof Number) {
                    metaJson.put(key, (Number) value);
                } else if (value instanceof Boolean) {
                    metaJson.put(key, (Boolean) value);
                } else if (value instanceof JSONObject) {
                    metaJson.put(key, (JSONObject) value);
                } else if (value instanceof JSONArray) {
                    metaJson.put(key, (JSONArray) value);
                } else if (value != null) {
                    metaJson.put(key, value.toString());
                }
            }
            json.put("metadata", metaJson);

            return json;
        } catch (Exception e) {
            Log.e(TAG, "序列化对话 JSON 失败: " + e.getMessage(), e);
            return new JSONObject();
        }
    }

    /**
     * 从 JSONObject 反序列化对话
     *
     * @param json 包含对话字段的 JSONObject
     * @return 解析得到的 Conversation 实例，解析失败时返回 null
     */
    public static Conversation fromJson(JSONObject json) {
        try {
            String id = json.optString("id", "");
            String title = json.optString("title", "");
            long createdAt = json.optLong("createdAt", System.currentTimeMillis());
            long updatedAt = json.optLong("updatedAt", createdAt);

            // 解析消息列表
            List<Message> messages = new ArrayList<Message>();
            JSONArray messagesArray = json.optJSONArray("messages");
            if (messagesArray != null) {
                messages = Message.fromJsonArray(messagesArray);
            }

            // 解析元数据
            Map<String, Object> metadata = new HashMap<String, Object>();
            JSONObject metaJson = json.optJSONObject("metadata");
            if (metaJson != null) {
                for (String key : metaJson.keySet()) {
                    Object value = metaJson.opt(key);
                    if (value != null && !JSONObject.NULL.equals(value)) {
                        metadata.put(key, value);
                    }
                }
            }

            if (id.isEmpty()) {
                Log.w(TAG, "反序列化失败：对话 ID 为空");
                return null;
            }

            return new Conversation(id, title, createdAt, updatedAt, messages, metadata);
        } catch (Exception e) {
            Log.e(TAG, "反序列化对话失败: " + e.getMessage(), e);
            return null;
        }
    }

    @Override
    public String toString() {
        return "Conversation{"
                + "id='" + id + '\''
                + ", title='" + title + '\''
                + ", createdAt=" + createdAt
                + ", updatedAt=" + updatedAt
                + ", messages=" + messages.size()
                + ", metadata=" + metadata.size()
                + '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Conversation that = (Conversation) o;
        return id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }
}