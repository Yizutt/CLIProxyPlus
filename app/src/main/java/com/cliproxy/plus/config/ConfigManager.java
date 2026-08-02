package com.cliproxy.plus.config;

import android.content.Context;
import android.util.Log;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * ConfigManager - 配置管理器
 * 加载/保存/热重载配置
 * 对应原版 internal/config/config.go
 */
public class ConfigManager {

    private static final String TAG = "ConfigManager";
    private static final String CONFIG_FILE = "config.yaml";
    private static final String CONFIG_JSON = "config.json";

    private static ConfigManager instance;
    private final Context context;
    private final Gson gson;

    private JsonObject config;

    private ConfigManager(Context context) {
        this.context = context.getApplicationContext();
        this.gson = new GsonBuilder().setPrettyPrinting().create();
        loadConfig();
    }

    public static synchronized ConfigManager getInstance(Context context) {
        if (instance == null) {
            instance = new ConfigManager(context);
        }
        return instance;
    }

    public static ConfigManager getInstance() {
        if (instance == null) {
            throw new IllegalStateException("ConfigManager not initialized. Call getInstance(Context) first.");
        }
        return instance;
    }

    /**
     * 加载配置
     */
    private void loadConfig() {
        File configFile = new File(context.getFilesDir(), CONFIG_JSON);
        if (configFile.exists()) {
            try (FileReader reader = new FileReader(configFile)) {
                config = JsonParser.parseReader(reader).getAsJsonObject();
                Log.i(TAG, "Config loaded from " + configFile.getAbsolutePath());
            } catch (IOException e) {
                Log.w(TAG, "Failed to load config, using defaults", e);
                config = getDefaultConfig();
            }
        } else {
            config = getDefaultConfig();
            saveConfig();
        }
    }

    /**
     * 保存配置
     */
    public void saveConfig() {
        File configFile = new File(context.getFilesDir(), CONFIG_JSON);
        try (FileWriter writer = new FileWriter(configFile)) {
            gson.toJson(config, writer);
            Log.i(TAG, "Config saved to " + configFile.getAbsolutePath());
        } catch (IOException e) {
            Log.e(TAG, "Failed to save config", e);
        }
    }

    /**
     * 获取默认配置
     */
    private JsonObject getDefaultConfig() {
        JsonObject defaults = new JsonObject();
        defaults.addProperty("host", "");
        defaults.addProperty("port", 8317);
        defaults.addProperty("debug", false);
        defaults.addProperty("incognito-browser", true);
        defaults.addProperty("request-retry", 3);
        defaults.addProperty("max-retry-interval", 30);
        defaults.addProperty("usage-statistics-enabled", true);

        // 路由策略
        JsonObject routing = new JsonObject();
        routing.addProperty("strategy", "round-robin");
        routing.addProperty("session-affinity", false);
        routing.addProperty("session-affinity-ttl", "1h");
        defaults.add("routing", routing);

        // OAuth excluded models
        defaults.add("oauth-excluded-models", new JsonObject());

        // OAuth model alias
        defaults.add("oauth-model-alias", new JsonObject());

        // API keys
        defaults.add("api-keys", new JsonObject());

        // Provider keys
        defaults.add("gemini-api-key", new JsonObject());
        defaults.add("claude-api-key", new JsonObject());
        defaults.add("codex-api-key", new JsonObject());
        defaults.add("xai-api-key", new JsonObject());
        defaults.add("vertex-api-key", new JsonObject());
        defaults.add("openai-compatibility", new JsonObject());

        return defaults;
    }

    /**
     * 获取配置值
     */
    public String getString(String key, String defaultValue) {
        if (config.has(key)) {
            return config.get(key).getAsString();
        }
        return defaultValue;
    }

    public int getInt(String key, int defaultValue) {
        if (config.has(key)) {
            return config.get(key).getAsInt();
        }
        return defaultValue;
    }

    public boolean getBoolean(String key, boolean defaultValue) {
        if (config.has(key)) {
            return config.get(key).getAsBoolean();
        }
        return defaultValue;
    }

    /**
     * 设置配置值
     */
    public void set(String key, String value) {
        config.addProperty(key, value);
        saveConfig();
    }

    public void set(String key, int value) {
        config.addProperty(key, value);
        saveConfig();
    }

    public void set(String key, boolean value) {
        config.addProperty(key, value);
        saveConfig();
    }

    public void set(String key, JsonObject value) {
        config.add(key, value);
        saveConfig();
    }

    /**
     * 获取完整配置 JSON
     */
    public String getConfigJson() {
        return gson.toJson(config);
    }

    /**
     * 获取配置对象
     */
    public JsonObject getConfig() {
        return config;
    }

    /**
     * 加载 YAML 配置
     */
    public void loadYamlConfig(String yamlContent) {
        // YAML 解析暂存 - 后续实现
        Log.w(TAG, "YAML config loading not yet implemented");
    }

    /**
     * 导出为 YAML
     */
    public String exportYaml() {
        // YAML 导出暂存
        return "# CLIProxy Plus Configuration\n" +
                "port: " + getInt("port", 8317) + "\n" +
                "debug: " + getBoolean("debug", false) + "\n";
    }

    /**
     * 热重载配置
     */
    public void reload() {
        loadConfig();
        Log.i(TAG, "Config reloaded");
    }
}