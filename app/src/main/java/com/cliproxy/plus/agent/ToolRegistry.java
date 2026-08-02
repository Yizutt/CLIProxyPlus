package com.cliproxy.plus.agent;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ToolRegistry - 工具注册表
 * AI Agent 工具的注册与管理中心，负责工具的注册、查询、分类过滤与执行调度。
 * 支持按类别过滤工具列表，每个工具包含名称、描述、参数 JSON Schema 和所需权限。
 */
public class ToolRegistry {

    private static final String TAG = "ToolRegistry";

    /** 默认工具分类：系统工具 */
    public static final String CATEGORY_SYSTEM = "system";

    /** 默认工具分类：文件操作 */
    public static final String CATEGORY_FILE = "file";

    /** 默认工具分类：网络请求 */
    public static final String CATEGORY_NETWORK = "network";

    /** 默认工具分类：数据处理 */
    public static final String CATEGORY_DATA = "data";

    /** 默认工具分类：自定义 */
    public static final String CATEGORY_CUSTOM = "custom";

    /** 工具名称 → 工具定义映射 */
    private final ConcurrentHashMap<String, ToolDefinition> toolMap;

    /** 分类 → 工具名称列表映射 */
    private final ConcurrentHashMap<String, List<String>> categoryIndex;

    /**
     * ToolDefinition - 工具定义
     * 描述一个 AI Agent 工具的元数据，包括名称、描述、参数 schema、权限和分类。
     */
    public static class ToolDefinition {

        private final String name;
        private final String description;
        private final JSONObject parametersSchema;
        private final List<String> requiredPermissions;
        private final String category;

        /**
         * 创建一个工具定义。
         *
         * @param name               工具名称，全局唯一
         * @param description        工具功能描述
         * @param parametersSchema   参数 JSON Schema 对象
         * @param requiredPermissions 所需权限列表
         * @param category           工具分类
         */
        public ToolDefinition(String name, String description,
                              JSONObject parametersSchema,
                              List<String> requiredPermissions,
                              String category) {
            this.name = name;
            this.description = description;
            this.parametersSchema = parametersSchema != null
                    ? parametersSchema : new JSONObject();
            this.requiredPermissions = requiredPermissions != null
                    ? Collections.unmodifiableList(new ArrayList<>(requiredPermissions))
                    : Collections.emptyList();
            this.category = category != null ? category : CATEGORY_SYSTEM;
        }

        /**
         * 创建一个工具定义（默认分类为 system）。
         *
         * @param name               工具名称
         * @param description        工具功能描述
         * @param parametersSchema   参数 JSON Schema 对象
         * @param requiredPermissions 所需权限列表
         */
        public ToolDefinition(String name, String description,
                              JSONObject parametersSchema,
                              List<String> requiredPermissions) {
            this(name, description, parametersSchema, requiredPermissions, CATEGORY_SYSTEM);
        }

        /**
         * 获取工具名称。
         *
         * @return 工具名称
         */
        public String getName() {
            return name;
        }

        /**
         * 获取工具功能描述。
         *
         * @return 描述文本
         */
        public String getDescription() {
            return description;
        }

        /**
         * 获取参数 JSON Schema。
         *
         * @return JSON Schema 对象
         */
        public JSONObject getParametersSchema() {
            return parametersSchema;
        }

        /**
         * 获取所需权限列表（不可变）。
         *
         * @return 权限字符串列表
         */
        public List<String> getRequiredPermissions() {
            return requiredPermissions;
        }

        /**
         * 获取工具分类。
         *
         * @return 分类名称
         */
        public String getCategory() {
            return category;
        }

        /**
         * 将工具定义转换为 JSONObject，便于序列化与调试。
         *
         * @return JSON 表示
         */
        public JSONObject toJson() {
            try {
                JSONObject json = new JSONObject();
                json.put("name", name);
                json.put("description", description);
                json.put("parametersSchema", parametersSchema);
                json.put("category", category);

                JSONArray perms = new JSONArray();
                for (String perm : requiredPermissions) {
                    perms.put(perm);
                }
                json.put("requiredPermissions", perms);

                return json;
            } catch (JSONException e) {
                Log.e(TAG, "Failed to serialize ToolDefinition to JSON", e);
                return new JSONObject();
            }
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

        @Override
        public String toString() {
            return "ToolDefinition{name='" + name + "', category='" + category + "'}";
        }
    }

    /**
     * 创建一个空的工具注册表。
     */
    public ToolRegistry() {
        this.toolMap = new ConcurrentHashMap<>();
        this.categoryIndex = new ConcurrentHashMap<>();
    }

    /**
     * 注册一个工具。如果同名工具已存在则覆盖旧定义。
     *
     * @param tool 工具定义，不可为 null
     * @throws IllegalArgumentException 如果工具名称为空
     */
    public void registerTool(ToolDefinition tool) {
        if (tool == null) {
            throw new IllegalArgumentException("tool must not be null");
        }
        if (tool.getName() == null || tool.getName().isEmpty()) {
            throw new IllegalArgumentException("tool name must not be empty");
        }

        ToolDefinition previous = toolMap.put(tool.getName(), tool);
        if (previous != null) {
            // 从旧分类中移除名称
            removeFromCategoryIndex(previous.getName(), previous.getCategory());
            Log.w(TAG, "Tool '" + tool.getName() + "' has been overwritten");
        }

        // 添加到分类索引
        addToCategoryIndex(tool.getName(), tool.getCategory());
        Log.d(TAG, "Registered tool: " + tool.getName() + " [" + tool.getCategory() + "]");
    }

    /**
     * 根据名称获取已注册的工具定义。
     *
     * @param name 工具名称
     * @return 工具定义，未找到时返回 null
     */
    public ToolDefinition getTool(String name) {
        if (name == null) {
            return null;
        }
        return toolMap.get(name);
    }

    /**
     * 获取所有已注册工具的不可变列表。
     *
     * @return 所有工具定义列表
     */
    public List<ToolDefinition> listTools() {
        return Collections.unmodifiableList(new ArrayList<>(toolMap.values()));
    }

    /**
     * 获取指定分类下的所有工具列表。
     *
     * @param category 分类名称，null 或空字符串等同于 {@link #listTools()}
     * @return 该分类下的工具定义列表（不可变），不会返回 null
     */
    public List<ToolDefinition> listTools(String category) {
        if (category == null || category.isEmpty()) {
            return listTools();
        }

        List<String> names = categoryIndex.get(category);
        if (names == null || names.isEmpty()) {
            return Collections.emptyList();
        }

        List<ToolDefinition> result = new ArrayList<>();
        for (String name : names) {
            ToolDefinition tool = toolMap.get(name);
            if (tool != null) {
                result.add(tool);
            }
        }
        return Collections.unmodifiableList(result);
    }

    /**
     * 获取所有已注册的分类名称列表。
     *
     * @return 分类名称列表（不可变）
     */
    public List<String> listCategories() {
        return Collections.unmodifiableList(new ArrayList<>(categoryIndex.keySet()));
    }

    /**
     * 执行指定名称的工具，解析 JSON 参数并返回执行结果。
     * <p>
     * 默认实现仅返回工具元数据作为结果。
     * 子类应重写此方法以提供实际工具执行逻辑。
     *
     * @param name   工具名称
     * @param params 工具参数 JSON 对象
     * @return 执行结果 JSON 对象
     * @throws IllegalArgumentException 如果工具未注册
     * @throws JSONException           如果参数解析失败
     */
    public JSONObject executeTool(String name, JSONObject params)
            throws IllegalArgumentException, JSONException {
        ToolDefinition tool = getTool(name);
        if (tool == null) {
            throw new IllegalArgumentException("Tool not found: " + name);
        }

        Log.d(TAG, "Executing tool: " + name + " with params: " + params);

        // 子类应重写此方法实现具体工具逻辑
        JSONObject result = new JSONObject();
        result.put("tool", name);
        result.put("status", "executed");
        result.put("description", tool.getDescription());
        result.put("params", params != null ? params : new JSONObject());
        return result;
    }

    /**
     * 检查指定名称的工具是否已注册。
     *
     * @param name 工具名称
     * @return 如果已注册则返回 true
     */
    public boolean hasTool(String name) {
        return name != null && toolMap.containsKey(name);
    }

    /**
     * 获取已注册工具的数量。
     *
     * @return 工具总数
     */
    public int size() {
        return toolMap.size();
    }

    /**
     * 清空注册表中的所有工具。
     */
    public void clear() {
        toolMap.clear();
        categoryIndex.clear();
        Log.d(TAG, "ToolRegistry has been cleared");
    }

    /**
     * 将工具名称添加到分类索引中。
     */
    private void addToCategoryIndex(String toolName, String category) {
        categoryIndex.putIfAbsent(category, Collections.synchronizedList(new ArrayList<>()));
        List<String> names = categoryIndex.get(category);
        synchronized (names) {
            if (!names.contains(toolName)) {
                names.add(toolName);
            }
        }
    }

    /**
     * 从分类索引中移除工具名称。
     */
    private void removeFromCategoryIndex(String toolName, String category) {
        List<String> names = categoryIndex.get(category);
        if (names != null) {
            synchronized (names) {
                names.remove(toolName);
                if (names.isEmpty()) {
                    categoryIndex.remove(category);
                }
            }
        }
    }

    /**
     * 将整个注册表导出为 JSONArray，便于调试和传输。
     *
     * @return JSONArray，每个元素是一个工具的 JSON 表示
     */
    public JSONArray exportToJson() {
        JSONArray array = new JSONArray();
        for (ToolDefinition tool : toolMap.values()) {
            array.put(tool.toJson());
        }
        return array;
    }
}