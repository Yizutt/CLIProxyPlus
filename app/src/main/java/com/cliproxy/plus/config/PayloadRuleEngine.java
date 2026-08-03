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
import android.widget.Spinner;
import android.widget.ArrayAdapter;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * PayloadRuleEngine - 载荷规则引擎
 * 管理默认/覆盖/过滤三类规则，支持通配符模型匹配和协议约束。
 * 对应原版 internal/config/payload_rules.go 的功能。
 */
public class PayloadRuleEngine {

    private static final String TAG = "PayloadRuleEngine";

    private final List<Rule> defaultRules = new ArrayList<>();
    private final List<Rule> overrideRules = new ArrayList<>();
    private final List<Rule> filterRules = new ArrayList<>();

    // ── 规则定义 ──────────────────────────────────────────────

    /**
     * 规则类型
     */
    public enum RuleType {
        DEFAULT,
        OVERRIDE,
        FILTER
    }

    /**
     * 单条规则
     */
    public static class Rule {
        private String id;
        private String name;
        private String modelPattern;   // 通配符模型匹配，如 "gpt-*"、"*"
        private String protocol;       // 协议约束，如 "*"、"http"、"websocket"、"sse"；null 或 "*" 表示不限制
        private JSONObject keyValues;  // DEFAULT/OVERRIDE 时使用：key -> value 映射
        private JSONArray filterFields; // FILTER 时使用：要过滤的字段名列表
        private boolean enabled;
        private int priority;

        public Rule() {
            this.id = java.util.UUID.randomUUID().toString().substring(0, 8);
            this.name = "";
            this.modelPattern = "*";
            this.protocol = "*";
            this.keyValues = new JSONObject();
            this.filterFields = new JSONArray();
            this.enabled = true;
            this.priority = 0;
        }

        public Rule(String id, String name, String modelPattern, String protocol,
                     JSONObject keyValues, JSONArray filterFields,
                     boolean enabled, int priority) {
            this.id = id;
            this.name = name;
            this.modelPattern = modelPattern;
            this.protocol = protocol;
            this.keyValues = keyValues;
            this.filterFields = filterFields;
            this.enabled = enabled;
            this.priority = priority;
        }

        // --- Getters / Setters ---

        public String getId() { return id; }
        public void setId(String id) { this.id = id; }

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }

        public String getModelPattern() { return modelPattern; }
        public void setModelPattern(String modelPattern) { this.modelPattern = modelPattern; }

        public String getProtocol() { return protocol; }
        public void setProtocol(String protocol) { this.protocol = protocol; }

        public JSONObject getKeyValues() { return keyValues; }
        public void setKeyValues(JSONObject keyValues) { this.keyValues = keyValues; }

        public JSONArray getFilterFields() { return filterFields; }
        public void setFilterFields(JSONArray filterFields) { this.filterFields = filterFields; }

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }

        public int getPriority() { return priority; }
        public void setPriority(int priority) { this.priority = priority; }

        /**
         * 序列化为 JSONObject
         */
        public JSONObject toJson() {
            try {
                JSONObject obj = new JSONObject();
                obj.put("id", id);
                obj.put("name", name);
                obj.put("modelPattern", modelPattern);
                obj.put("protocol", protocol);
                obj.put("keyValues", keyValues);
                obj.put("filterFields", filterFields);
                obj.put("enabled", enabled);
                obj.put("priority", priority);
                return obj;
            } catch (Exception e) {
                Log.e(TAG, "Failed to serialize rule", e);
                return new JSONObject();
            }
        }

        /**
         * 从 JSONObject 反序列化
         */
        public static Rule fromJson(JSONObject obj) {
            Rule rule = new Rule();
            try {
                if (obj.has("id")) rule.id = obj.getString("id");
                if (obj.has("name")) rule.name = obj.getString("name");
                if (obj.has("modelPattern")) rule.modelPattern = obj.getString("modelPattern");
                if (obj.has("protocol")) rule.protocol = obj.getString("protocol");
                if (obj.has("keyValues")) rule.keyValues = obj.getJSONObject("keyValues");
                if (obj.has("filterFields")) rule.filterFields = obj.getJSONArray("filterFields");
                if (obj.has("enabled")) rule.enabled = obj.getBoolean("enabled");
                if (obj.has("priority")) rule.priority = obj.getInt("priority");
            } catch (Exception e) {
                Log.e(TAG, "Failed to deserialize rule", e);
            }
            return rule;
        }

        @Override
        public String toString() {
            return "Rule{" +
                    "id='" + id + '\'' +
                    ", name='" + name + '\'' +
                    ", pattern='" + modelPattern + '\'' +
                    ", protocol='" + protocol + '\'' +
                    ", enabled=" + enabled +
                    ", priority=" + priority +
                    '}';
        }
    }

    // ── 通配符匹配 ────────────────────────────────────────────

    /**
     * 检查模型名是否匹配通配符模式。
     * 支持 '*'（匹配任意字符序列）和 '?'（匹配单个字符）。
     */
    public static boolean matchesWildcard(String pattern, String modelName) {
        if (pattern == null || modelName == null) {
            return false;
        }
        // 快速路径
        if ("*".equals(pattern)) {
            return true;
        }
        if (pattern.equals(modelName)) {
            return true;
        }
        // 递归通配符匹配
        return wildcardMatch(pattern, modelName, 0, 0);
    }

    private static boolean wildcardMatch(String pattern, String text, int pi, int ti) {
        int pLen = pattern.length();
        int tLen = text.length();

        while (pi < pLen && ti < tLen) {
            char p = pattern.charAt(pi);
            if (p == '*') {
                // '*' 匹配零个或多个字符：尝试跳过 pattern 中的 '*'
                while (pi < pLen && pattern.charAt(pi) == '*') {
                    pi++;
                }
                if (pi >= pLen) {
                    return true; // 结尾的 '*' 匹配剩余所有
                }
                // 尝试在 text 中匹配后续 pattern
                char next = pattern.charAt(pi);
                while (ti < tLen) {
                    if ((next == '?' || text.charAt(ti) == next)
                            && wildcardMatch(pattern, text, pi, ti)) {
                        return true;
                    }
                    ti++;
                }
                return false;
            } else if (p == '?') {
                // '?' 匹配任意单个字符
                pi++;
                ti++;
            } else {
                // 普通字符必须相等
                if (p != text.charAt(ti)) {
                    return false;
                }
                pi++;
                ti++;
            }
        }

        // 跳过 pattern 尾部多余的 '*'
        while (pi < pLen && pattern.charAt(pi) == '*') {
            pi++;
        }

        return pi >= pLen && ti >= tLen;
    }

    /**
     * 检查协议是否匹配约束。
     * protocolConstraint 为 null 或 "*" 时表示不限制。
     */
    public static boolean matchesProtocol(String protocolConstraint, String actualProtocol) {
        if (protocolConstraint == null || "*".equals(protocolConstraint)) {
            return true;
        }
        if (actualProtocol == null) {
            return false;
        }
        return protocolConstraint.equalsIgnoreCase(actualProtocol);
    }

    // ── 规则管理与应用 ────────────────────────────────────────

    /**
     * 添加默认规则
     */
    public void addDefaultRule(Rule rule) {
        defaultRules.add(rule);
        Log.d(TAG, "Added default rule: " + rule.getName());
    }

    /**
     * 添加覆盖规则
     */
    public void addOverrideRule(Rule rule) {
        overrideRules.add(rule);
        Log.d(TAG, "Added override rule: " + rule.getName());
    }

    /**
     * 添加过滤规则
     */
    public void addFilterRule(Rule rule) {
        filterRules.add(rule);
        Log.d(TAG, "Added filter rule: " + rule.getName());
    }

    public List<Rule> getDefaultRules() { return defaultRules; }
    public List<Rule> getOverrideRules() { return overrideRules; }
    public List<Rule> getFilterRules() { return filterRules; }

    public void clearDefaultRules() { defaultRules.clear(); }
    public void clearOverrideRules() { overrideRules.clear(); }
    public void clearFilterRules() { filterRules.clear(); }

    /**
     * 从 JSON 批量导入规则
     *
     * @param json 包含 rules 数组的 JSON 对象，每条规则有 type 字段
     */
    public void importRules(JSONObject json) {
        try {
            if (json.has("defaultRules")) {
                JSONArray arr = json.getJSONArray("defaultRules");
                for (int i = 0; i < arr.length(); i++) {
                    addDefaultRule(Rule.fromJson(arr.getJSONObject(i)));
                }
            }
            if (json.has("overrideRules")) {
                JSONArray arr = json.getJSONArray("overrideRules");
                for (int i = 0; i < arr.length(); i++) {
                    addOverrideRule(Rule.fromJson(arr.getJSONObject(i)));
                }
            }
            if (json.has("filterRules")) {
                JSONArray arr = json.getJSONArray("filterRules");
                for (int i = 0; i < arr.length(); i++) {
                    addFilterRule(Rule.fromJson(arr.getJSONObject(i)));
                }
            }
            Log.i(TAG, "Rules imported");
        } catch (Exception e) {
            Log.e(TAG, "Failed to import rules", e);
        }
    }

    /**
     * 导出所有规则为 JSON
     */
    public JSONObject exportRules() {
        try {
            JSONObject obj = new JSONObject();
            obj.put("defaultRules", rulesToJsonArray(defaultRules));
            obj.put("overrideRules", rulesToJsonArray(overrideRules));
            obj.put("filterRules", rulesToJsonArray(filterRules));
            return obj;
        } catch (Exception e) {
            Log.e(TAG, "Failed to export rules", e);
            return new JSONObject();
        }
    }

    private JSONArray rulesToJsonArray(List<Rule> rules) {
        JSONArray arr = new JSONArray();
        for (Rule rule : rules) {
            arr.put(rule.toJson());
        }
        return arr;
    }

    // ── 核心规则应用方法 ──────────────────────────────────────

    /**
     * 应用默认规则。
     * 仅在 payload 中不存在目标字段时写入默认值。
     *
     * @param payload  原始请求载荷
     * @param model    当前模型名
     * @param protocol 通信协议（如 "http", "websocket", "sse"）
     * @return 应用默认规则后的 payload
     */
    public JSONObject applyDefaultRules(JSONObject payload, String model, String protocol) {
        if (payload == null) {
            return new JSONObject();
        }
        Log.d(TAG, "Applying default rules for model=" + model + ", protocol=" + protocol);

        // 按优先级排序（低优先级在前，高优先级在后依次覆盖）
        List<Rule> sorted = new ArrayList<>(defaultRules);
        sorted.sort((a, b) -> Integer.compare(a.getPriority(), b.getPriority()));

        for (Rule rule : sorted) {
            if (!rule.isEnabled()) continue;
            if (!matchesWildcard(rule.getModelPattern(), model)) continue;
            if (!matchesProtocol(rule.getProtocol(), protocol)) continue;

            JSONObject kv = rule.getKeyValues();
            Iterator<String> keys = kv.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                if (!payload.has(key)) {
                    try {
                        Object value = kv.get(key);
                        payload.put(key, value);
                        Log.v(TAG, "Default set: " + key + " = " + value);
                    } catch (Exception e) {
                        Log.w(TAG, "Failed to set default key: " + key, e);
                    }
                }
            }
        }
        return payload;
    }

    /**
     * 应用覆盖规则。
     * 强制写入指定字段的值，覆盖 payload 中已有的值。
     *
     * @param payload  原始请求载荷
     * @param model    当前模型名
     * @param protocol 通信协议
     * @return 应用覆盖规则后的 payload
     */
    public JSONObject applyOverrideRules(JSONObject payload, String model, String protocol) {
        if (payload == null) {
            return new JSONObject();
        }
        Log.d(TAG, "Applying override rules for model=" + model + ", protocol=" + protocol);

        List<Rule> sorted = new ArrayList<>(overrideRules);
        sorted.sort((a, b) -> Integer.compare(a.getPriority(), b.getPriority()));

        for (Rule rule : sorted) {
            if (!rule.isEnabled()) continue;
            if (!matchesWildcard(rule.getModelPattern(), model)) continue;
            if (!matchesProtocol(rule.getProtocol(), protocol)) continue;

            JSONObject kv = rule.getKeyValues();
            Iterator<String> keys = kv.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                try {
                    Object value = kv.get(key);
                    payload.put(key, value);
                    Log.v(TAG, "Override set: " + key + " = " + value);
                } catch (Exception e) {
                    Log.w(TAG, "Failed to override key: " + key, e);
                }
            }
        }
        return payload;
    }

    /**
     * 应用过滤规则。
     * 移除 payload 中匹配指定字段名的键值对。
     *
     * @param payload  原始请求载荷
     * @param model    当前模型名
     * @param protocol 通信协议
     * @return 应用过滤规则后的 payload
     */
    public JSONObject applyFilterRules(JSONObject payload, String model, String protocol) {
        if (payload == null) {
            return new JSONObject();
        }
        Log.d(TAG, "Applying filter rules for model=" + model + ", protocol=" + protocol);

        List<Rule> sorted = new ArrayList<>(filterRules);
        sorted.sort((a, b) -> Integer.compare(a.getPriority(), b.getPriority()));

        for (Rule rule : sorted) {
            if (!rule.isEnabled()) continue;
            if (!matchesWildcard(rule.getModelPattern(), model)) continue;
            if (!matchesProtocol(rule.getProtocol(), protocol)) continue;

            JSONArray fields = rule.getFilterFields();
            for (int i = 0; i < fields.length(); i++) {
                try {
                    String fieldName = fields.getString(i);
                    if (payload.has(fieldName)) {
                        payload.remove(fieldName);
                        Log.v(TAG, "Filtered field: " + fieldName);
                    }
                } catch (Exception e) {
                    Log.w(TAG, "Failed to filter field", e);
                }
            }
        }
        return payload;
    }

    /**
     * 依次应用全部三类规则（默认 → 覆盖 → 过滤），
     * 是发送请求前的统一入口。
     */
    public JSONObject applyAllRules(JSONObject payload, String model, String protocol) {
        payload = applyDefaultRules(payload, model, protocol);
        payload = applyOverrideRules(payload, model, protocol);
        payload = applyFilterRules(payload, model, protocol);
        return payload;
    }

    // ── 规则管理 UI ──────────────────────────────────────────

    // 主题色常量
    private static final int COLOR_BG = Color.parseColor("#1E1E2E");
    private static final int COLOR_PRIMARY = Color.parseColor("#7C3AED");
    private static final int COLOR_TEXT = Color.parseColor("#CDD6F4");
    private static final int COLOR_SURFACE = Color.parseColor("#2A2A3E");
    private static final int COLOR_BORDER = Color.parseColor("#3A3A50");

    /**
     * 创建规则管理对话框的内容视图。
     * 返回一个包含全部规则列表和管理按钮的 LinearLayout。
     */
    public LinearLayout createRuleManagementView(android.content.Context context) {
        LinearLayout root = new LinearLayout(context);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(24, 24, 24, 24);
        root.setBackgroundColor(COLOR_BG);

        // 标题
        TextView title = new TextView(context);
        title.setText("Payload Rule Engine");
        title.setTextSize(20);
        title.setTextColor(COLOR_PRIMARY);
        title.setGravity(Gravity.CENTER);
        title.setPadding(0, 0, 0, 24);
        root.addView(title);

        // 各规则类型面板
        root.addView(createRuleTypePanel(context, "Default Rules", defaultRules, RuleType.DEFAULT));
        root.addView(createRuleTypePanel(context, "Override Rules", overrideRules, RuleType.OVERRIDE));
        root.addView(createRuleTypePanel(context, "Filter Rules", filterRules, RuleType.FILTER));

        return root;
    }

    private LinearLayout createRuleTypePanel(android.content.Context context,
                                              String label,
                                              List<Rule> rules,
                                              RuleType type) {
        LinearLayout panel = new LinearLayout(context);
        panel.setOrientation(LinearLayout.VERTICAL);
        panel.setPadding(0, 0, 0, 16);

        // 类型标题行
        LinearLayout headerRow = new LinearLayout(context);
        headerRow.setOrientation(LinearLayout.HORIZONTAL);
        headerRow.setGravity(Gravity.CENTER_VERTICAL);

        TextView labelView = new TextView(context);
        labelView.setText(label + " (" + rules.size() + ")");
        labelView.setTextSize(16);
        labelView.setTextColor(COLOR_PRIMARY);
        labelView.setLayoutParams(new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        headerRow.addView(labelView);

        Button addBtn = new Button(context);
        addBtn.setText("+ Add");
        addBtn.setTextColor(Color.WHITE);
        addBtn.setBackgroundColor(COLOR_PRIMARY);
        addBtn.setPadding(16, 8, 16, 8);
        addBtn.setOnClickListener(v -> {
            Rule newRule = new Rule();
            rules.add(newRule);
            Log.d(TAG, "Added new " + type + " rule: " + newRule.getId());
            Toast.makeText(context, "Rule added", Toast.LENGTH_SHORT).show();
        });
        headerRow.addView(addBtn);

        panel.addView(headerRow);

        // 规则列表
        for (int i = 0; i < rules.size(); i++) {
            Rule rule = rules.get(i);
            panel.addView(createRuleCard(context, rule, i, rules, type));
        }

        return panel;
    }

    private View createRuleCard(android.content.Context context,
                                 Rule rule,
                                 int index,
                                 List<Rule> rules,
                                 RuleType type) {
        LinearLayout card = new LinearLayout(context);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(16, 12, 16, 12);
        card.setBackgroundColor(COLOR_SURFACE);
        card.setElevation(2f);

        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        params.setMargins(0, 8, 0, 8);
        card.setLayoutParams(params);

        // 圆角通过设置背景 Drawable 实现 — 使用纯色背景 + margin 视觉近似
        card.setPadding(16, 12, 16, 12);

        // 行 1: 名称 + 开关
        LinearLayout row1 = new LinearLayout(context);
        row1.setOrientation(LinearLayout.HORIZONTAL);
        row1.setGravity(Gravity.CENTER_VERTICAL);

        EditText nameInput = new EditText(context);
        nameInput.setText(rule.getName());
        nameInput.setHint("Rule name");
        nameInput.setTextColor(COLOR_TEXT);
        nameInput.setHintTextColor(Color.GRAY);
        nameInput.setBackgroundColor(Color.TRANSPARENT);
        nameInput.setLayoutParams(new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        final int idx = index;
        nameInput.setOnFocusChangeListener((v, hasFocus) -> {
            if (!hasFocus) {
                rule.setName(nameInput.getText().toString().trim());
            }
        });
        row1.addView(nameInput);

        // 启用/禁用切换按钮
        Button toggleBtn = new Button(context);
        toggleBtn.setText(rule.isEnabled() ? "ON" : "OFF");
        toggleBtn.setTextColor(Color.WHITE);
        toggleBtn.setBackgroundColor(rule.isEnabled() ? COLOR_PRIMARY : Color.GRAY);
        toggleBtn.setPadding(12, 4, 12, 4);
        toggleBtn.setOnClickListener(v -> {
            rule.setEnabled(!rule.isEnabled());
            toggleBtn.setText(rule.isEnabled() ? "ON" : "OFF");
            toggleBtn.setBackgroundColor(rule.isEnabled() ? COLOR_PRIMARY : Color.GRAY);
        });
        row1.addView(toggleBtn);

        // 删除按钮
        ImageButton deleteBtn = new ImageButton(context);
        deleteBtn.setText("X");
        deleteBtn.setBackgroundColor(Color.TRANSPARENT);
        deleteBtn.setPadding(8, 4, 8, 4);
        deleteBtn.setOnClickListener(v -> {
            rules.remove(rule);
            Log.d(TAG, "Removed rule: " + rule.getId());
            Toast.makeText(context, "Rule removed", Toast.LENGTH_SHORT).show();
        });
        row1.addView(deleteBtn);

        card.addView(row1);

        // 行 2: 模型匹配模式 + 协议
        LinearLayout row2 = new LinearLayout(context);
        row2.setOrientation(LinearLayout.HORIZONTAL);
        row2.setGravity(Gravity.CENTER_VERTICAL);
        row2.setPadding(0, 8, 0, 0);

        TextView modelLabel = new TextView(context);
        modelLabel.setText("Model:");
        modelLabel.setTextColor(COLOR_TEXT);
        modelLabel.setTextSize(12);
        row2.addView(modelLabel);

        EditText modelInput = new EditText(context);
        modelInput.setText(rule.getModelPattern());
        modelInput.setHint("*");
        modelInput.setTextColor(COLOR_TEXT);
        modelInput.setHintTextColor(Color.GRAY);
        modelInput.setBackgroundColor(Color.TRANSPARENT);
        modelInput.setLayoutParams(new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        modelInput.setOnFocusChangeListener((v, hasFocus) -> {
            if (!hasFocus) {
                rule.setModelPattern(modelInput.getText().toString().trim());
            }
        });
        row2.addView(modelInput);

        TextView protoLabel = new TextView(context);
        protoLabel.setText(" Proto:");
        protoLabel.setTextColor(COLOR_TEXT);
        protoLabel.setTextSize(12);
        row2.addView(protoLabel);

        Spinner protoSpinner = new Spinner(context);
        ArrayAdapter<String> adapter = new ArrayAdapter<>(context,
                android.R.layout.simple_spinner_item,
                new String[]{"* (any)", "http", "websocket", "sse"});
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        protoSpinner.setAdapter(adapter);

        // 设置当前选中项
        String currentProto = rule.getProtocol();
        if ("*".equals(currentProto) || currentProto == null) protoSpinner.setSelection(0);
        else if ("http".equalsIgnoreCase(currentProto)) protoSpinner.setSelection(1);
        else if ("websocket".equalsIgnoreCase(currentProto)) protoSpinner.setSelection(2);
        else if ("sse".equalsIgnoreCase(currentProto)) protoSpinner.setSelection(3);

        protoSpinner.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(android.widget.AdapterView<?> parent, View view, int pos, long id) {
                String[] vals = {"*", "http", "websocket", "sse"};
                rule.setProtocol(vals[pos]);
            }
            @Override
            public void onNothingSelected(android.widget.AdapterView<?> parent) {}
        });
        row2.addView(protoSpinner);

        card.addView(row2);

        // 行 3: Key-Values (DEFAULT/OVERRIDE) 或 Filter Fields (FILTER)
        if (type == RuleType.FILTER) {
            LinearLayout row3 = new LinearLayout(context);
            row3.setOrientation(LinearLayout.HORIZONTAL);
            row3.setPadding(0, 8, 0, 0);

            TextView fvLabel = new TextView(context);
            fvLabel.setText("Filter fields (comma separated):");
            fvLabel.setTextColor(COLOR_TEXT);
            fvLabel.setTextSize(12);
            row3.addView(fvLabel);

            // 将 filterFields 拼接为逗号分隔字符串
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < rule.getFilterFields().length(); i++) {
                try { sb.append(rule.getFilterFields().getString(i)); } catch (Exception e) { /* skip */ }
                if (i < rule.getFilterFields().length() - 1) sb.append(", ");
            }

            EditText filterInput = new EditText(context);
            filterInput.setText(sb.toString());
            filterInput.setHint("field1, field2");
            filterInput.setTextColor(COLOR_TEXT);
            filterInput.setHintTextColor(Color.GRAY);
            filterInput.setBackgroundColor(Color.TRANSPARENT);
            filterInput.setLayoutParams(new LinearLayout.LayoutParams(
                    0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
            filterInput.setOnFocusChangeListener((v, hasFocus) -> {
                if (!hasFocus) {
                    JSONArray arr = new JSONArray();
                    String raw = filterInput.getText().toString().trim();
                    if (!raw.isEmpty()) {
                        for (String part : raw.split(",")) {
                            arr.put(part.trim());
                        }
                    }
                    rule.setFilterFields(arr);
                }
            });
            row3.addView(filterInput);
            card.addView(row3);
        } else {
            // DEFAULT 或 OVERRIDE — 显示 key-value 编辑行
            LinearLayout row3 = new LinearLayout(context);
            row3.setOrientation(LinearLayout.HORIZONTAL);
            row3.setPadding(0, 8, 0, 0);

            TextView kvLabel = new TextView(context);
            kvLabel.setText("Key:Value (JSON):");
            kvLabel.setTextColor(COLOR_TEXT);
            kvLabel.setTextSize(12);
            row3.addView(kvLabel);

            EditText kvInput = new EditText(context);
            kvInput.setText(rule.getKeyValues().toString());
            kvInput.setHint("{\"key\": \"value\"}");
            kvInput.setTextColor(COLOR_TEXT);
            kvInput.setHintTextColor(Color.GRAY);
            kvInput.setBackgroundColor(Color.TRANSPARENT);
            kvInput.setLayoutParams(new LinearLayout.LayoutParams(
                    0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
            kvInput.setOnFocusChangeListener((v, hasFocus) -> {
                if (!hasFocus) {
                    try {
                        String raw = kvInput.getText().toString().trim();
                        if (!raw.isEmpty()) {
                            rule.setKeyValues(new JSONObject(raw));
                        }
                    } catch (Exception e) {
                        Log.w(TAG, "Invalid JSON for keyValues", e);
                    }
                }
            });
            row3.addView(kvInput);
            card.addView(row3);
        }

        // 行 4: 优先级
        LinearLayout row4 = new LinearLayout(context);
        row4.setOrientation(LinearLayout.HORIZONTAL);
        row4.setPadding(0, 8, 0, 0);

        TextView prioLabel = new TextView(context);
        prioLabel.setText("Priority:");
        prioLabel.setTextColor(COLOR_TEXT);
        prioLabel.setTextSize(12);
        row4.addView(prioLabel);

        EditText prioInput = new EditText(context);
        prioInput.setText(String.valueOf(rule.getPriority()));
        prioInput.setHint("0");
        prioInput.setTextColor(COLOR_TEXT);
        prioInput.setHintTextColor(Color.GRAY);
        prioInput.setBackgroundColor(Color.TRANSPARENT);
        prioInput.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);
        prioInput.setLayoutParams(new LinearLayout.LayoutParams(
                80, ViewGroup.LayoutParams.WRAP_CONTENT));
        prioInput.setOnFocusChangeListener((v, hasFocus) -> {
            if (!hasFocus) {
                try {
                    rule.setPriority(Integer.parseInt(prioInput.getText().toString().trim()));
                } catch (NumberFormatException e) {
                    rule.setPriority(0);
                }
            }
        });
        row4.addView(prioInput);

        card.addView(row4);

        return card;
    }

    /**
     * 将规则管理视图包装在 ScrollView 中，适合嵌入 Dialog。
     */
    public ScrollView createRuleManagementScrollView(android.content.Context context) {
        ScrollView scrollView = new ScrollView(context);
        scrollView.setBackgroundColor(COLOR_BG);
        scrollView.addView(createRuleManagementView(context));
        return scrollView;
    }

    /**
     * 在一个 AlertDialog 中显示规则管理界面。
     */
    public void showRuleManagementDialog(android.content.Context context) {
        android.app.AlertDialog.Builder builder = new android.app.AlertDialog.Builder(context);
        builder.setTitle("Payload Rule Engine");
        builder.setView(createRuleManagementScrollView(context));
        builder.setPositiveButton("Close", (dialog, which) -> dialog.dismiss());
        builder.setNegativeButton("Export", (dialog, which) -> {
            String json = exportRules().toString();
            Log.i(TAG, "Exported rules: " + json);
            Toast.makeText(context, "Rules exported to logcat", Toast.LENGTH_SHORT).show();
        });
        builder.setNeutralButton("Clear All", (dialog, which) -> {
            clearDefaultRules();
            clearOverrideRules();
            clearFilterRules();
            Toast.makeText(context, "All rules cleared", Toast.LENGTH_SHORT).show();
        });
        builder.create().show();
    }
}