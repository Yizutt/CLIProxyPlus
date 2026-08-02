package com.cliproxy.plus.agent.model;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * ToolDefinition - AI Agent 工具定义
 * 描述一个可供 AI 智能体调用的工具，包含名称、描述、参数 schema、
 * 确认要求、超时时间和分类信息。用于生成 LLM 函数调用（Function Calling）
 * 所需的工具定义 JSON。
 */
public class ToolDefinition {

    private static final String TAG = "ToolDefinition";

    /** 工具名称，用于 LLM 识别和调用 */
    private final String name;

    /** 工具描述，告知 LLM 该工具的功能和用途 */
    private final String description;

    /** 工具参数，采用 JSON Schema 格式描述入参结构 */
    private final JSONObject parameters;

    /** 是否需要用户确认后才执行 */
    private final boolean requiresConfirmation;

    /** 工具执行超时时间（秒） */
    private final int timeoutSeconds;

    /** 工具分类，如 "system"、"file"、"network" 等 */
    private final String category;

    /**
     * 构造一个完整的工具定义
     *
     * @param name                工具名称
     * @param description         工具描述
     * @param parameters          参数 JSON Schema
     * @param requiresConfirmation 是否需要用户确认
     * @param timeoutSeconds      超时时间（秒）
     * @param category            工具分类
     */
    public ToolDefinition(String name, String description, JSONObject parameters,
                          boolean requiresConfirmation, int timeoutSeconds, String category) {
        this.name = name;
        this.description = description;
        this.parameters = parameters != null ? parameters : new JSONObject();
        this.requiresConfirmation = requiresConfirmation;
        this.timeoutSeconds = timeoutSeconds;
        this.category = category != null ? category : "general";
    }

    /**
     * 构造一个不需要确认的默认工具定义
     *
     * @param name           工具名称
     * @param description    工具描述
     * @param parameters     参数 JSON Schema
     * @param timeoutSeconds 超时时间（秒）
     * @param category       工具分类
     */
    public ToolDefinition(String name, String description, JSONObject parameters,
                          int timeoutSeconds, String category) {
        this(name, description, parameters, false, timeoutSeconds, category);
    }

    /**
     * 获取工具名称
     *
     * @return 工具名称
     */
    public String getName() {
        return name;
    }

    /**
     * 获取工具描述
     *
     * @return 工具描述
     */
    public String getDescription() {
        return description;
    }

    /**
     * 获取参数 JSON Schema
     *
     * @return 参数定义
     */
    public JSONObject getParameters() {
        return parameters;
    }

    /**
     * 是否需要用户确认
     *
     * @return true 表示需要用户确认后执行
     */
    public boolean isRequiresConfirmation() {
        return requiresConfirmation;
    }

    /**
     * 获取工具超时时间（秒）
     *
     * @return 超时时间
     */
    public int getTimeoutSeconds() {
        return timeoutSeconds;
    }

    /**
     * 获取工具分类
     *
     * @return 分类名称
     */
    public String getCategory() {
        return category;
    }

    /**
     * 将当前工具定义转换为 LLM 函数调用（Function Calling）所需的 JSON 格式。
     * <p>
     * 输出格式遵循 OpenAI Tool / Anthropic Tool 规范：
     * <pre>
     * {
     *   "type": "function",
     *   "function": {
     *     "name": "...",
     *     "description": "...",
     *     "parameters": { ... }
     *   }
     * }
     * </pre>
     *
     * @return 表示该工具定义的 JSONObject
     */
    public JSONObject toJson() {
        try {
            JSONObject function = new JSONObject();
            function.put("name", name);
            function.put("description", description);

            // 确保 parameters 包含 type 和 properties 字段
            if (!parameters.has("type")) {
                parameters.put("type", "object");
            }
            if (!parameters.has("properties")) {
                parameters.put("properties", new JSONObject());
            }
            function.put("parameters", parameters);

            JSONObject tool = new JSONObject();
            tool.put("type", "function");
            tool.put("function", function);

            return tool;
        } catch (Exception e) {
            Log.e(TAG, "构建工具定义 JSON 失败: " + e.getMessage(), e);
            return new JSONObject();
        }
    }

    /**
     * 将当前工具定义转换为包含扩展属性的完整 JSON 表示。
     * 包含确认要求和超时等元数据，用于内部调度。
     *
     * @return 包含全部字段的 JSONObject
     */
    public JSONObject toFullJson() {
        try {
            JSONObject json = toJson();
            json.put("requiresConfirmation", requiresConfirmation);
            json.put("timeoutSeconds", timeoutSeconds);
            json.put("category", category);
            return json;
        } catch (Exception e) {
            Log.e(TAG, "构建完整工具 JSON 失败: " + e.getMessage(), e);
            return new JSONObject();
        }
    }

    /**
     * 从 JSONObject 反序列化工具定义
     *
     * @param json 包含工具字段的 JSONObject
     * @return 解析得到的 ToolDefinition 实例，解析失败时返回 null
     */
    public static ToolDefinition fromJson(JSONObject json) {
        try {
            String name = json.optString("name", "");
            String description = json.optString("description", "");
            JSONObject parameters = json.optJSONObject("parameters");
            boolean requiresConfirmation = json.optBoolean("requiresConfirmation", false);
            int timeoutSeconds = json.optInt("timeoutSeconds", 30);
            String category = json.optString("category", "general");

            if (name.isEmpty()) {
                Log.w(TAG, "反序列化失败：工具名称为空");
                return null;
            }

            return new ToolDefinition(name, description, parameters,
                    requiresConfirmation, timeoutSeconds, category);
        } catch (Exception e) {
            Log.e(TAG, "反序列化工具定义失败: " + e.getMessage(), e);
            return null;
        }
    }

    /**
     * 构建一个空参数（无入参）的参数 JSON Schema
     *
     * @return 表示无参数的 JSON Schema
     */
    public static JSONObject emptyParameters() {
        try {
            JSONObject params = new JSONObject();
            params.put("type", "object");
            params.put("properties", new JSONObject());
            params.put("required", new JSONArray());
            return params;
        } catch (Exception e) {
            Log.e(TAG, "创建空参数 Schema 失败: " + e.getMessage(), e);
            return new JSONObject();
        }
    }

    @Override
    public String toString() {
        return "ToolDefinition{"
                + "name='" + name + '\''
                + ", description='" + description + '\''
                + ", requiresConfirmation=" + requiresConfirmation
                + ", timeoutSeconds=" + timeoutSeconds
                + ", category='" + category + '\''
                + '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ToolDefinition that = (ToolDefinition) o;
        return name.equals(that.name);
    }

    @Override
    public int hashCode() {
        return name.hashCode();
    }
}