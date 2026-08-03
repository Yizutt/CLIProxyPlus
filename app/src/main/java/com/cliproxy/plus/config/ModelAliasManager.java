package com.cliproxy.plus.config;

import android.graphics.Color;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * ModelAliasManager - 模型别名管理器
 * 管理 OAuth 提供者和 API Key 的模型名称别名。
 * 支持全局别名 (oauth-model-alias) 和 per-auth 别名。
 * 对应原版 internal/config/config.go 中的 oauth-model-alias 配置。
 *
 * 别名查找顺序:
 *   1. 当前 channel 的私有别名
 *   2. 全局别名 (channel = "global")
 */
public class ModelAliasManager {

    private static final String TAG = "ModelAliasManager";

    /** 全局别名 channel 标识 */
    public static final String CHANNEL_GLOBAL = "global";

    /** 配置中 oauth-model-alias 的键名 */
    private static final String CONFIG_ALIAS_KEY = "oauth-model-alias";

    // ── 主题色常量 ──────────────────────────────────────────────

    private static final int COLOR_BG = Color.parseColor("#1E1E2E");
    private static final int COLOR_PRIMARY = Color.parseColor("#7C3AED");
    private static final int COLOR_TEXT = Color.parseColor("#CDD6F4");
    private static final int COLOR_SURFACE = Color.parseColor("#2A2A3E");
    private static final int COLOR_BORDER = Color.parseColor("#3A3A50");
    private static final int COLOR_DANGER = Color.parseColor("#EF4444");

    // ── 别名条目定义 ────────────────────────────────────────────

    /**
     * 单个别名条目。
     * 记录原始模型名 -> 别名的映射关系及其行为标志。
     */
    public static class AliasEntry {
        private String originalName;
        private String alias;
        private boolean fork;         // fork 模式：保留原始名称并添加别名
        private boolean forceMapping; // forceMapping 模式：重写响应中的 model 字段

        public AliasEntry() {
            this.originalName = "";
            this.alias = "";
            this.fork = false;
            this.forceMapping = false;
        }

        public AliasEntry(String originalName, String alias, boolean fork, boolean forceMapping) {
            this.originalName = originalName;
            this.alias = alias;
            this.fork = fork;
            this.forceMapping = forceMapping;
        }

        // --- Getters / Setters ---

        public String getOriginalName() { return originalName; }
        public void setOriginalName(String originalName) { this.originalName = originalName; }

        public String getAlias() { return alias; }
        public void setAlias(String alias) { this.alias = alias; }

        public boolean isFork() { return fork; }
        public void setFork(boolean fork) { this.fork = fork; }

        public boolean isForceMapping() { return forceMapping; }
        public void setForceMapping(boolean forceMapping) { this.forceMapping = forceMapping; }

        /**
         * 序列化为 JSONObject。
         * 格式: { "name": "...", "alias": "...", "fork": bool, "forceMapping": bool }
         */
        public JSONObject toJson() {
            try {
                JSONObject obj = new JSONObject();
                obj.put("name", originalName);
                obj.put("alias", alias);
                obj.put("fork", fork);
                obj.put("forceMapping", forceMapping);
                return obj;
            } catch (Exception e) {
                Log.e(TAG, "Failed to serialize AliasEntry", e);
                return new JSONObject();
            }
        }

        /**
         * 从 JSONObject 反序列化。
         * 兼容格式: { "name": "...", "alias": "...", "fork": bool, "forceMapping": bool }
         */
        public static AliasEntry fromJson(JSONObject obj) {
            AliasEntry entry = new AliasEntry();
            try {
                if (obj.has("name")) entry.originalName = obj.getString("name");
                if (obj.has("alias")) entry.alias = obj.getString("alias");
                if (obj.has("fork")) entry.fork = obj.getBoolean("fork");
                if (obj.has("forceMapping")) entry.forceMapping = obj.getBoolean("forceMapping");
            } catch (Exception e) {
                Log.e(TAG, "Failed to deserialize AliasEntry", e);
            }
            return entry;
        }

        @Override
        public String toString() {
            return "AliasEntry{" +
                    "originalName='" + originalName + '\'' +
                    ", alias='" + alias + '\'' +
                    ", fork=" + fork +
                    ", forceMapping=" + forceMapping +
                    '}';
        }
    }

    // ── 内部数据结构 ────────────────────────────────────────────

    /**
     * 别名存储结构。
     * channel -> (originalName -> AliasEntry)
     */
    private final Map<String, Map<String, AliasEntry>> aliasMap = new HashMap<>();

    /** 可选: 与 ConfigManager 配合持久化 */
    private ConfigManager configManager;

    // ── 构造方法 ────────────────────────────────────────────────

    public ModelAliasManager() {
        Log.d(TAG, "ModelAliasManager initialized");
    }

    /**
     * 使用 ConfigManager 构造，加载持久化的别名配置。
     *
     * @param configManager 配置管理器实例
     */
    public ModelAliasManager(ConfigManager configManager) {
        this.configManager = configManager;
        loadFromConfig();
        Log.i(TAG, "ModelAliasManager initialized with ConfigManager");
    }

    // ── 核心方法 ────────────────────────────────────────────────

    /**
     * 解析模型名称，返回最终使用的模型名。
     * 查找顺序:
     *   1. 当前 channel 的私有别名
     *   2. 全局别名 (CHANNEL_GLOBAL)
     * 未找到别名时返回原始名称。
     *
     * @param channel   认证渠道标识 (如 "auth:providerName" 或 "global")
     * @param modelName 原始模型名称
     * @return 解析后的模型名称，未匹配时返回原始名称
     */
    public String resolveAlias(String channel, String modelName) {
        if (channel == null || modelName == null) {
            Log.w(TAG, "resolveAlias: channel or modelName is null");
            return modelName;
        }

        Log.d(TAG, "resolveAlias: channel=" + channel + ", modelName=" + modelName);

        // 1. 查找 channel 私有别名
        String resolved = resolveFromChannel(channel, modelName);
        if (resolved != null) {
            Log.d(TAG, "resolveAlias: found in channel '" + channel + "' -> " + resolved);
            return resolved;
        }

        // 2. 回退到全局别名
        if (!CHANNEL_GLOBAL.equals(channel)) {
            resolved = resolveFromChannel(CHANNEL_GLOBAL, modelName);
            if (resolved != null) {
                Log.d(TAG, "resolveAlias: found in global aliases -> " + resolved);
                return resolved;
            }
        }

        Log.d(TAG, "resolveAlias: no alias found, returning original: " + modelName);
        return modelName;
    }

    /**
     * 在指定 channel 中查找模型别名。
     *
     * @param channel   渠道标识
     * @param modelName 原始模型名称
     * @return 别名，如果不存在则返回 null
     */
    private String resolveFromChannel(String channel, String modelName) {
        Map<String, AliasEntry> channelMap = aliasMap.get(channel);
        if (channelMap == null) {
            return null;
        }

        // 精确匹配
        AliasEntry entry = channelMap.get(modelName);
        if (entry != null) {
            return entry.getAlias();
        }

        // 通配符匹配: 查找 key 为 "*" 的通配条目
        AliasEntry wildcard = channelMap.get("*");
        if (wildcard != null) {
            return wildcard.getAlias();
        }

        return null;
    }

    /**
     * 注册一个模型别名。
     *
     * @param channel      渠道标识 (如 "global", "auth:providerName")
     * @param name         原始模型名称 (支持 "*" 通配)
     * @param alias        目标别名
     * @param fork          fork 模式: 保留原始名称，额外添加别名
     * @param forceMapping  forceMapping 模式: 重写响应中的 model 字段
     */
    public void registerAlias(String channel, String name, String alias,
                              boolean fork, boolean forceMapping) {
        if (channel == null || name == null || alias == null) {
            Log.w(TAG, "registerAlias: channel, name, or alias is null");
            return;
        }

        if (name.isEmpty() || alias.isEmpty()) {
            Log.w(TAG, "registerAlias: name or alias is empty");
            return;
        }

        // 获取或创建 channel 的映射表
        Map<String, AliasEntry> channelMap = aliasMap.computeIfAbsent(channel, k -> new LinkedHashMap<>());

        AliasEntry entry = new AliasEntry(name, alias, fork, forceMapping);
        channelMap.put(name, entry);

        Log.i(TAG, "registerAlias: channel=" + channel
                + ", name=" + name
                + ", alias=" + alias
                + ", fork=" + fork
                + ", forceMapping=" + forceMapping);

        // 持久化到 ConfigManager
        saveToConfig();
    }

    /**
     * 列出指定 channel 的所有别名条目。
     *
     * @param channel 渠道标识，null 或空时返回所有 channel 的别名
     * @return 别名条目列表（按注册顺序排列）
     */
    public List<AliasEntry> listAliases(String channel) {
        List<AliasEntry> result = new ArrayList<>();

        if (channel == null || channel.isEmpty()) {
            // 列出所有 channel 的全部别名
            for (Map.Entry<String, Map<String, AliasEntry>> channelEntry : aliasMap.entrySet()) {
                for (AliasEntry entry : channelEntry.getValue().values()) {
                    result.add(entry);
                }
            }
        } else {
            Map<String, AliasEntry> channelMap = aliasMap.get(channel);
            if (channelMap != null) {
                result.addAll(channelMap.values());
            }
        }

        Log.d(TAG, "listAliases: channel=" + (channel != null ? channel : "ALL")
                + ", count=" + result.size());
        return result;
    }

    /**
     * 删除指定 channel 中的一条别名。
     *
     * @param channel 渠道标识
     * @param name    原始模型名称
     * @return 删除成功返回 true
     */
    public boolean removeAlias(String channel, String name) {
        if (channel == null || name == null) {
            return false;
        }

        Map<String, AliasEntry> channelMap = aliasMap.get(channel);
        if (channelMap == null) {
            return false;
        }

        AliasEntry removed = channelMap.remove(name);
        if (removed != null) {
            Log.i(TAG, "removeAlias: channel=" + channel + ", name=" + name);
            // 清理空 channel
            if (channelMap.isEmpty()) {
                aliasMap.remove(channel);
            }
            saveToConfig();
            return true;
        }

        return false;
    }

    /**
     * 清空所有别名。
     */
    public void clearAll() {
        aliasMap.clear();
        saveToConfig();
        Log.i(TAG, "clearAll: all aliases cleared");
    }

    /**
     * 清空指定 channel 的所有别名。
     *
     * @param channel 渠道标识
     */
    public void clearChannel(String channel) {
        if (channel == null) {
            return;
        }
        aliasMap.remove(channel);
        saveToConfig();
        Log.i(TAG, "clearChannel: channel=" + channel + " cleared");
    }

    // ── 处理响应模型映射 ────────────────────────────────────────

    /**
     * 对响应 JSON 中的 model 字段应用 forceMapping。
     * 遍历所有 forceMapping=true 的别名，如果响应中的 model 匹配别名，
     * 则将其重写为原始名称。
     * <p>
     * 典型的场景: 发送请求时使用别名，但响应中需要还原为原始模型名。
     *
     * @param response 原始响应 JSON
     * @param channel  当前认证渠道
     * @return 应用 forceMapping 后的响应 JSON
     */
    public JSONObject applyForceMapping(JSONObject response, String channel) {
        if (response == null) {
            return new JSONObject();
        }

        if (!response.has("model")) {
            return response;
        }

        try {
            String responseModel = response.getString("model");
            String resolved = resolveAlias(channel, responseModel);

            // 如果解析结果与原始名称不同，说明有别名映射
            if (!responseModel.equals(resolved)) {
                // 查找对应别名条目，检查是否启用 forceMapping
                AliasEntry entry = findAliasEntry(channel, responseModel);
                if (entry == null && !CHANNEL_GLOBAL.equals(channel)) {
                    entry = findAliasEntry(CHANNEL_GLOBAL, responseModel);
                }

                if (entry != null && entry.isForceMapping()) {
                    response.put("model", entry.getOriginalName());
                    Log.d(TAG, "applyForceMapping: rewrote model '" + responseModel
                            + "' -> '" + entry.getOriginalName() + "'");
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "applyForceMapping: failed to process response", e);
        }

        return response;
    }

    /**
     * 在指定 channel 中查找别名条目。
     */
    private AliasEntry findAliasEntry(String channel, String modelName) {
        Map<String, AliasEntry> channelMap = aliasMap.get(channel);
        if (channelMap == null) {
            return null;
        }
        // 先精确匹配
        AliasEntry entry = channelMap.get(modelName);
        if (entry != null) {
            return entry;
        }
        // 再尝试通配匹配
        for (Map.Entry<String, AliasEntry> e : channelMap.entrySet()) {
            String key = e.getKey();
            if ("*".equals(key)) {
                continue; // 单独处理精确通配
            }
            // 检查是否通过通配符匹配到这个条目
            if (PayloadRuleEngine.matchesWildcard(key, modelName)) {
                return e.getValue();
            }
        }
        // 最后尝试精确的通配 "*"
        return channelMap.get("*");
    }

    // ── 持久化 ──────────────────────────────────────────────────

    /**
     * 从 ConfigManager 加载别名配置。
     * 期望 config 格式:
     * {
     *   "oauth-model-alias": {
     *     "global": [ { "name": "...", "alias": "...", "fork": bool, "forceMapping": bool }, ... ],
     *     "auth:providerName": [ ... ]
     *   }
     * }
     */
    public void loadFromConfig() {
        if (configManager == null) {
            Log.w(TAG, "loadFromConfig: configManager is null");
            return;
        }

        aliasMap.clear();

        try {
            JSONObject config = new JSONObject(configManager.getConfigJson());
            if (!config.has(CONFIG_ALIAS_KEY)) {
                Log.d(TAG, "loadFromConfig: no '" + CONFIG_ALIAS_KEY + "' in config");
                return;
            }

            JSONObject aliasConfig = config.getJSONObject(CONFIG_ALIAS_KEY);
            Iterator<String> channels = aliasConfig.keys();

            while (channels.hasNext()) {
                String channel = channels.next();
                JSONArray aliasArray = aliasConfig.optJSONArray(channel);

                if (aliasArray == null) {
                    continue;
                }

                Map<String, AliasEntry> channelMap = new LinkedHashMap<>();
                for (int i = 0; i < aliasArray.length(); i++) {
                    JSONObject entryObj = aliasArray.getJSONObject(i);
                    AliasEntry entry = AliasEntry.fromJson(entryObj);
                    channelMap.put(entry.getOriginalName(), entry);
                }
                aliasMap.put(channel, channelMap);
            }

            Log.i(TAG, "loadFromConfig: loaded aliases for " + aliasMap.size() + " channels");
        } catch (Exception e) {
            Log.e(TAG, "loadFromConfig: failed to parse config", e);
        }
    }

    /**
     * 将当前别名保存到 ConfigManager。
     * 格式:
     * {
     *   "oauth-model-alias": {
     *     "global": [ ... ],
     *     "auth:providerName": [ ... ]
     *   }
     * }
     */
    public void saveToConfig() {
        if (configManager == null) {
            Log.w(TAG, "saveToConfig: configManager is null, skipping");
            return;
        }

        try {
            JSONObject aliasConfig = new JSONObject();

            for (Map.Entry<String, Map<String, AliasEntry>> channelEntry : aliasMap.entrySet()) {
                String channel = channelEntry.getKey();
                JSONArray aliasArray = new JSONArray();

                for (AliasEntry entry : channelEntry.getValue().values()) {
                    aliasArray.put(entry.toJson());
                }

                aliasConfig.put(channel, aliasArray);
            }

            // 使用 ConfigManager 的 patchConfig 方法更新配置
            JSONObject patch = new JSONObject();
            patch.put(CONFIG_ALIAS_KEY, aliasConfig);
            configManager.patchConfig(patch);

            Log.i(TAG, "saveToConfig: saved aliases for " + aliasMap.size() + " channels");
        } catch (Exception e) {
            Log.e(TAG, "saveToConfig: failed to save config", e);
        }
    }

    // ── 导出/导入 ────────────────────────────────────────────────

    /**
     * 导出所有别名配置为 JSONObject。
     * 格式与 saveToConfig 一致。
     */
    public JSONObject exportAliases() {
        try {
            JSONObject aliasConfig = new JSONObject();

            for (Map.Entry<String, Map<String, AliasEntry>> channelEntry : aliasMap.entrySet()) {
                String channel = channelEntry.getKey();
                JSONArray aliasArray = new JSONArray();

                for (AliasEntry entry : channelEntry.getValue().values()) {
                    aliasArray.put(entry.toJson());
                }

                aliasConfig.put(channel, aliasArray);
            }

            return aliasConfig;
        } catch (Exception e) {
            Log.e(TAG, "exportAliases: failed", e);
            return new JSONObject();
        }
    }

    /**
     * 从 JSONObject 导入别名配置。
     *
     * @param aliasConfig 格式同 exportAliases 的输出
     */
    public void importAliases(JSONObject aliasConfig) {
        if (aliasConfig == null) {
            return;
        }

        aliasMap.clear();
        Iterator<String> channels = aliasConfig.keys();

        while (channels.hasNext()) {
            String channel = channels.next();
            try {
                JSONArray aliasArray = aliasConfig.optJSONArray(channel);
                if (aliasArray == null) {
                    continue;
                }

                Map<String, AliasEntry> channelMap = new LinkedHashMap<>();
                for (int i = 0; i < aliasArray.length(); i++) {
                    AliasEntry entry = AliasEntry.fromJson(aliasArray.getJSONObject(i));
                    channelMap.put(entry.getOriginalName(), entry);
                }
                aliasMap.put(channel, channelMap);
            } catch (Exception e) {
                Log.w(TAG, "importAliases: failed to parse channel '" + channel + "'", e);
            }
        }

        saveToConfig();
        Log.i(TAG, "importAliases: imported " + aliasMap.size() + " channels");
    }

    // ── 工具方法 ─────────────────────────────────────────────────

    /**
     * 获取所有已注册的 channel 名称。
     */
    public List<String> getChannels() {
        return new ArrayList<>(aliasMap.keySet());
    }

    /**
     * 获取指定 channel 的别名数量。
     */
    public int getAliasCount(String channel) {
        Map<String, AliasEntry> channelMap = aliasMap.get(channel);
        return channelMap != null ? channelMap.size() : 0;
    }

    /**
     * 检查指定 channel 中是否存在某别名的 forceMapping。
     * 用于判断是否需要对响应进行重写。
     */
    public boolean hasForceMapping(String channel, String modelName) {
        AliasEntry entry = findAliasEntry(channel, modelName);
        if (entry == null && !CHANNEL_GLOBAL.equals(channel)) {
            entry = findAliasEntry(CHANNEL_GLOBAL, modelName);
        }
        return entry != null && entry.isForceMapping();
    }

    // ── UI 构建 ──────────────────────────────────────────────────

    /**
     * 创建别名管理视图（包含所有 channel 的面板）。
     */
    public LinearLayout createAliasManagementView(android.content.Context context) {
        LinearLayout root = new LinearLayout(context);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(24, 24, 24, 24);
        root.setBackgroundColor(COLOR_BG);

        // 标题
        TextView title = new TextView(context);
        title.setText("Model Alias Manager");
        title.setTextSize(20);
        title.setTextColor(COLOR_PRIMARY);
        title.setGravity(Gravity.CENTER);
        title.setPadding(0, 0, 0, 24);
        root.addView(title);

        // 全局别名面板
        root.addView(createChannelPanel(context, CHANNEL_GLOBAL, "Global Aliases"));

        // 其他 channel 面板
        for (String channel : aliasMap.keySet()) {
            if (CHANNEL_GLOBAL.equals(channel)) {
                continue;
            }
            root.addView(createChannelPanel(context, channel, "Channel: " + channel));
        }

        // 添加新 channel 的行
        LinearLayout addChannelRow = new LinearLayout(context);
        addChannelRow.setOrientation(LinearLayout.HORIZONTAL);
        addChannelRow.setGravity(Gravity.CENTER_VERTICAL);
        addChannelRow.setPadding(0, 16, 0, 0);

        EditText channelInput = new EditText(context);
        channelInput.setHint("New channel name");
        channelInput.setTextColor(COLOR_TEXT);
        channelInput.setHintTextColor(Color.GRAY);
        channelInput.setBackgroundColor(COLOR_SURFACE);
        channelInput.setPadding(12, 8, 12, 8);
        channelInput.setLayoutParams(new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        addChannelRow.addView(channelInput);

        Button addChannelBtn = new Button(context);
        addChannelBtn.setText("+ Channel");
        addChannelBtn.setTextColor(Color.WHITE);
        addChannelBtn.setBackgroundColor(COLOR_PRIMARY);
        addChannelBtn.setPadding(16, 8, 16, 8);
        addChannelBtn.setOnClickListener(v -> {
            String ch = channelInput.getText().toString().trim();
            if (!ch.isEmpty() && !aliasMap.containsKey(ch)) {
                aliasMap.put(ch, new LinkedHashMap<>());
                Log.i(TAG, "Created new channel: " + ch);
                Toast.makeText(context, "Channel '" + ch + "' created", Toast.LENGTH_SHORT).show();
                channelInput.setText("");
            }
        });
        addChannelRow.addView(addChannelBtn);

        root.addView(addChannelRow);

        // 清空所有按钮
        Button clearAllBtn = new Button(context);
        clearAllBtn.setText("Clear All Aliases");
        clearAllBtn.setTextColor(Color.WHITE);
        clearAllBtn.setBackgroundColor(COLOR_DANGER);
        clearAllBtn.setPadding(16, 8, 16, 8);
        clearAllBtn.setGravity(Gravity.CENTER);
        clearAllBtn.setOnClickListener(v -> {
            clearAll();
            Toast.makeText(context, "All aliases cleared", Toast.LENGTH_SHORT).show();
        });

        LinearLayout btnRow = new LinearLayout(context);
        btnRow.setGravity(Gravity.CENTER);
        btnRow.setPadding(0, 16, 0, 0);
        btnRow.addView(clearAllBtn);
        root.addView(btnRow);

        return root;
    }

    /**
     * 创建单个 channel 的别名面板。
     */
    private LinearLayout createChannelPanel(android.content.Context context,
                                            String channel, String label) {
        LinearLayout panel = new LinearLayout(context);
        panel.setOrientation(LinearLayout.VERTICAL);
        panel.setPadding(0, 0, 0, 16);

        // 标题行
        LinearLayout headerRow = new LinearLayout(context);
        headerRow.setOrientation(LinearLayout.HORIZONTAL);
        headerRow.setGravity(Gravity.CENTER_VERTICAL);

        TextView labelView = new TextView(context);
        labelView.setText(label + " (" + getAliasCount(channel) + ")");
        labelView.setTextSize(16);
        labelView.setTextColor(COLOR_PRIMARY);
        labelView.setLayoutParams(new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        headerRow.addView(labelView);

        Button addAliasBtn = new Button(context);
        addAliasBtn.setText("+ Alias");
        addAliasBtn.setTextColor(Color.WHITE);
        addAliasBtn.setBackgroundColor(COLOR_PRIMARY);
        addAliasBtn.setPadding(16, 8, 16, 8);
        addAliasBtn.setOnClickListener(v -> {
            AliasEntry entry = new AliasEntry();
            Map<String, AliasEntry> channelMap = aliasMap.computeIfAbsent(
                    channel, k -> new LinkedHashMap<>());
            channelMap.put("", entry);
            Log.d(TAG, "Added new alias entry to channel: " + channel);
            Toast.makeText(context, "Alias entry added", Toast.LENGTH_SHORT).show();
        });
        headerRow.addView(addAliasBtn);

        panel.addView(headerRow);

        // 别名列表
        Map<String, AliasEntry> channelMap = aliasMap.get(channel);
        if (channelMap != null) {
            List<Map.Entry<String, AliasEntry>> entries = new ArrayList<>(channelMap.entrySet());
            for (int i = 0; i < entries.size(); i++) {
                Map.Entry<String, AliasEntry> me = entries.get(i);
                panel.addView(createAliasCard(context, me.getKey(), me.getValue(),
                        channel, channelMap));
            }
        }

        return panel;
    }

    /**
     * 创建单个别名条目的编辑卡片。
     */
    private View createAliasCard(android.content.Context context,
                                 final String entryKey,
                                 final AliasEntry entry,
                                 final String channel,
                                 final Map<String, AliasEntry> channelMap) {
        LinearLayout card = new LinearLayout(context);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(16, 12, 16, 12);
        card.setBackgroundColor(COLOR_SURFACE);
        card.setElevation(2f);

        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        params.setMargins(0, 8, 0, 8);
        card.setLayoutParams(params);

        // ── 行 1: 原始名称 + 别名 ──
        LinearLayout row1 = new LinearLayout(context);
        row1.setOrientation(LinearLayout.HORIZONTAL);
        row1.setGravity(Gravity.CENTER_VERTICAL);

        TextView nameLabel = new TextView(context);
        nameLabel.setText("Name:");
        nameLabel.setTextColor(COLOR_TEXT);
        nameLabel.setTextSize(12);
        row1.addView(nameLabel);

        EditText nameInput = new EditText(context);
        nameInput.setText(entry.getOriginalName());
        nameInput.setHint("model name or *");
        nameInput.setTextColor(COLOR_TEXT);
        nameInput.setHintTextColor(Color.GRAY);
        nameInput.setBackgroundColor(Color.TRANSPARENT);
        nameInput.setLayoutParams(new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        final String currentKey = entryKey;
        nameInput.setOnFocusChangeListener((v, hasFocus) -> {
            if (!hasFocus) {
                String newName = nameInput.getText().toString().trim();
                if (!newName.equals(currentKey) && !currentKey.isEmpty()) {
                    // key 已变更，需要重新映射
                    channelMap.remove(currentKey);
                    entry.setOriginalName(newName);
                    channelMap.put(newName, entry);
                } else {
                    entry.setOriginalName(newName);
                }
                saveToConfig();
            }
        });
        row1.addView(nameInput);

        TextView aliasLabel = new TextView(context);
        aliasLabel.setText(" Alias:");
        aliasLabel.setTextColor(COLOR_TEXT);
        aliasLabel.setTextSize(12);
        row1.addView(aliasLabel);

        EditText aliasInput = new EditText(context);
        aliasInput.setText(entry.getAlias());
        aliasInput.setHint("alias name");
        aliasInput.setTextColor(COLOR_TEXT);
        aliasInput.setHintTextColor(Color.GRAY);
        aliasInput.setBackgroundColor(Color.TRANSPARENT);
        aliasInput.setLayoutParams(new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        aliasInput.setOnFocusChangeListener((v, hasFocus) -> {
            if (!hasFocus) {
                entry.setAlias(aliasInput.getText().toString().trim());
                saveToConfig();
            }
        });
        row1.addView(aliasInput);

        // 删除按钮
        ImageButton deleteBtn = new ImageButton(context);
        deleteBtn.setText("X");
        deleteBtn.setBackgroundColor(Color.TRANSPARENT);
        deleteBtn.setPadding(8, 4, 8, 4);
        deleteBtn.setOnClickListener(v -> {
            channelMap.remove(entry.getOriginalName());
            if (channelMap.isEmpty()) {
                aliasMap.remove(channel);
            }
            saveToConfig();
            Log.d(TAG, "Removed alias: " + entry.getOriginalName()
                    + " from channel: " + channel);
            Toast.makeText(context, "Alias removed", Toast.LENGTH_SHORT).show();
        });
        row1.addView(deleteBtn);

        card.addView(row1);

        // ── 行 2: Fork + ForceMapping 开关 ──
        LinearLayout row2 = new LinearLayout(context);
        row2.setOrientation(LinearLayout.HORIZONTAL);
        row2.setGravity(Gravity.CENTER_VERTICAL);
        row2.setPadding(0, 8, 0, 0);

        // Fork 按钮
        Button forkBtn = new Button(context);
        forkBtn.setText(entry.isFork() ? "Fork: ON" : "Fork: OFF");
        forkBtn.setTextColor(Color.WHITE);
        forkBtn.setBackgroundColor(entry.isFork() ? COLOR_PRIMARY : Color.GRAY);
        forkBtn.setPadding(12, 6, 12, 6);
        forkBtn.setOnClickListener(v -> {
            entry.setFork(!entry.isFork());
            forkBtn.setText(entry.isFork() ? "Fork: ON" : "Fork: OFF");
            forkBtn.setBackgroundColor(entry.isFork() ? COLOR_PRIMARY : Color.GRAY);
            saveToConfig();
        });
        row2.addView(forkBtn);

        // ForceMapping 按钮
        Button forceBtn = new Button(context);
        forceBtn.setText(entry.isForceMapping() ? "ForceMap: ON" : "ForceMap: OFF");
        forceBtn.setTextColor(Color.WHITE);
        forceBtn.setBackgroundColor(entry.isForceMapping() ? COLOR_PRIMARY : Color.GRAY);
        forceBtn.setPadding(12, 6, 12, 6);
        forceBtn.setOnClickListener(v -> {
            entry.setForceMapping(!entry.isForceMapping());
            forceBtn.setText(entry.isForceMapping() ? "ForceMap: ON" : "ForceMap: OFF");
            forceBtn.setBackgroundColor(entry.isForceMapping() ? COLOR_PRIMARY : Color.GRAY);
            saveToConfig();
        });
        row2.addView(forceBtn);

        // 状态提示
        TextView statusText = new TextView(context);
        StringBuilder statusSb = new StringBuilder();
        if (entry.isFork()) {
            statusSb.append(" [Fork: keep '" + entry.getOriginalName() + "']");
        }
        if (entry.isForceMapping()) {
            statusSb.append(" [ForceMap: rewrite response model]");
        }
        if (statusSb.length() > 0) {
            statusText.setText(statusSb.toString());
        } else {
            statusText.setText(" [Direct mapping]");
        }
        statusText.setTextColor(Color.parseColor("#A0A0B8"));
        statusText.setTextSize(11);
        statusText.setPadding(8, 0, 0, 0);
        row2.addView(statusText);

        card.addView(row2);

        return card;
    }

    /**
     * 将别名管理视图包装在 ScrollView 中，适合嵌入 Dialog。
     */
    public ScrollView createAliasManagementScrollView(android.content.Context context) {
        ScrollView scrollView = new ScrollView(context);
        scrollView.setBackgroundColor(COLOR_BG);
        scrollView.addView(createAliasManagementView(context));
        return scrollView;
    }

    /**
     * 在 AlertDialog 中显示别名管理界面。
     */
    public void showAliasManagementDialog(android.content.Context context) {
        android.app.AlertDialog.Builder builder = new android.app.AlertDialog.Builder(context);
        builder.setTitle("Model Alias Manager");
        builder.setView(createAliasManagementScrollView(context));
        builder.setPositiveButton("Close", (dialog, which) -> {
            saveToConfig();
            dialog.dismiss();
        });
        builder.setNegativeButton("Export", (dialog, which) -> {
            String json = exportAliases().toString();
            Log.i(TAG, "Exported aliases: " + json);
            Toast.makeText(context, "Aliases exported to logcat", Toast.LENGTH_SHORT).show();
        });
        builder.setNeutralButton("Reload", (dialog, which) -> {
            loadFromConfig();
            Toast.makeText(context, "Aliases reloaded from config", Toast.LENGTH_SHORT).show();
        });
        builder.create().show();
    }
}