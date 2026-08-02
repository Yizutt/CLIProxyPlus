package com.cliproxy.plus.auth.kiro;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * TruncationDetector - 启发式截断检测器
 * <p>
 * 检测 Kiro 流式响应中的工具调用截断。在流式传输过程中，网络中断、
 * 服务端错误或客户端超时可能导致工具调用响应被截断，进而引发
 * JSON 解析异常或下游逻辑错误。
 * <p>
 * 检测策略包括：
 * <ul>
 *   <li><b>JSON 完整性检测</b> - 验证顶层结构是否为合法 JSON，检查括号匹配</li>
 *   <li><b>必需字段检测</b> - 确认工具调用 JSON 包含所有必需字段（如 {@code name}、{@code arguments}）</li>
 *   <li><b>写工具内容长度检测</b> - 对 write/create/update 类工具，检测内容是否异常短</li>
 *   <li><b>流终止标记检测</b> - 检测响应是否以预期的终止标记（如 {@code ]}、{@code }}）结尾</li>
 *   <li><b>字段边界截断检测</b> - 检测字符串值是否在引号内被截断</li>
 * </ul>
 * <p>
 * 对应原版 CLIProxyAPIPlus/internal/auth/kiro/ 中的流处理启发式截断检测逻辑。
 */
public class TruncationDetector {

    private static final String TAG = "TruncationDetector";

    // ================================================================
    //  截断判定常量
    // ================================================================

    /** 判定为截断的分数阈值（0.0 ~ 1.0），超过此值视为已截断 */
    private static final double TRUNCATION_THRESHOLD = 0.5;

    /** 写工具内容的最小合理长度（字节） */
    private static final int MIN_WRITE_TOOL_CONTENT_LENGTH = 50;

    /** 单次 isTruncated 检查的最大扫描长度，超出部分不扫描 */
    private static final int MAX_CHUNK_SCAN_LENGTH = 8192;

    /** 写工具关键词集合（名称中包含这些关键词的工具被视为写工具） */
    private static final String[] WRITE_TOOL_KEYWORDS = {
            "write", "create", "update", "edit", "patch", "put",
            "upload", "save", "store", "add", "insert", "modify",
            "replace", "delete", "remove", "rename", "copy", "move"
    };

    /** 工具调用中必需的顶级字段 */
    private static final String[] REQUIRED_TOOL_FIELDS = {
            "name", "arguments"
    };

    /** 流终止标记集合，响应应以这些标记结尾 */
    private static final char[] STREAM_TERMINATORS = { '}', ']', '"', '\n' };

    // ================================================================
    //  编译正则
    // ================================================================

    /** 检测字符串字段是否在引号内被截断 */
    private static final Pattern TRUNCATED_STRING_PATTERN =
            Pattern.compile("\"[^\"]*$");

    /** 检测 JSON 中未闭合的字符串值（引号后无内容） */
    private static final Pattern UNCLOSED_STRING_PATTERN =
            Pattern.compile(":\"([^\"]*)$");

    /** 检测 JSON 中截断的字段名 */
    private static final Pattern TRUNCATED_FIELD_PATTERN =
            Pattern.compile("\"\\w+$");

    /** 检测 JSON 数组或对象是否未闭合 */
    private static final Pattern UNCLOSED_BRACKET_PATTERN =
            Pattern.compile("[\\[\\{][^\\]\\}]*$");

    // ================================================================
    //  内部类：ScanReport
    // ================================================================

    /**
     * 扫描报告，包含截断检测的详细结果。
     */
    public static class ScanReport {

        /** 是否被判定为截断 */
        public final boolean truncated;

        /** 截断置信度分数（0.0 ~ 1.0） */
        public final double score;

        /** 截断原因列表 */
        public final List<String> reasons;

        /** 检测到的异常列表 */
        public final List<Throwable> errors;

        /** 原始内容长度 */
        public final int contentLength;

        /** 扫描耗时（毫秒） */
        public final long scanDurationMs;

        ScanReport(boolean truncated, double score, List<String> reasons,
                   List<Throwable> errors, int contentLength, long scanDurationMs) {
            this.truncated = truncated;
            this.score = score;
            this.reasons = Collections.unmodifiableList(reasons);
            this.errors = Collections.unmodifiableList(errors);
            this.contentLength = contentLength;
            this.scanDurationMs = scanDurationMs;
        }

        /**
         * 返回截断原因摘要（以 "; " 分隔）。
         *
         * @return 原因摘要字符串
         */
        public String getReasonSummary() {
            return String.join("; ", reasons);
        }

        @Override
        public String toString() {
            return "ScanReport{"
                    + "truncated=" + truncated
                    + ", score=" + score
                    + ", reasons=" + reasons
                    + ", contentLength=" + contentLength
                    + ", scanDurationMs=" + scanDurationMs
                    + '}';
        }
    }

    /**
     * ScanReport 构建器。
     */
    public static class ScanReportBuilder {
        private final List<String> reasons = new ArrayList<>();
        private final List<Throwable> errors = new ArrayList<>();
        private final int contentLength;
        private final long startTime;

        ScanReportBuilder(int contentLength) {
            this.contentLength = contentLength;
            this.startTime = System.currentTimeMillis();
        }

        ScanReportBuilder addReason(String reason) {
            reasons.add(reason);
            return this;
        }

        ScanReportBuilder addError(Throwable error) {
            errors.add(error);
            return this;
        }

        ScanReport build(double score) {
            long duration = System.currentTimeMillis() - startTime;
            return new ScanReport(
                    score >= TRUNCATION_THRESHOLD,
                    Math.min(1.0, Math.max(0.0, score)),
                    reasons,
                    errors,
                    contentLength,
                    duration
            );
        }
    }

    // ================================================================
    //  构造
    // ================================================================

    /**
     * 创建一个 TruncationDetector 实例。
     */
    public TruncationDetector() {
        Log.d(TAG, "TruncationDetector initialized");
    }

    // ================================================================
    //  公有方法
    // ================================================================

    /**
     * 快速检测单个响应块是否包含截断迹象。
     * <p>
     * 此方法对响应块执行轻量级检查，适用于流式传输中每个数据块的
     * 实时检测。检查内容包括：
     * <ul>
     *   <li>空块或过短块</li>
     *   <li>JSON 括号不匹配</li>
     *   <li>字符串值在引号内截断</li>
     *   <li>缺少流终止标记</li>
     * </ul>
     *
     * @param responseChunk 需要检测的响应块字符串，可以为 null 或空
     * @return true 如果检测到截断迹象，false 否则
     */
    public boolean isTruncated(String responseChunk) {
        if (responseChunk == null || responseChunk.trim().isEmpty()) {
            Log.w(TAG, "isTruncated: response chunk is null or empty");
            return true;
        }

        try {
            String trimmed = responseChunk.trim();
            int len = Math.min(trimmed.length(), MAX_CHUNK_SCAN_LENGTH);
            String scanRegion = trimmed.substring(0, len);

            // 检查是否以 JSON 对象或数组开头
            if (!scanRegion.startsWith("{") && !scanRegion.startsWith("[")) {
                // 非 JSON 结构，检查是否包含明显的截断信号
                if (detectUnclosedQuotes(scanRegion)) {
                    Log.d(TAG, "isTruncated: unclosed quotes detected in chunk");
                    return true;
                }
                if (detectTruncatedField(scanRegion)) {
                    Log.d(TAG, "isTruncated: truncated field name detected in chunk");
                    return true;
                }
                // 非 JSON 块不判定为截断，交给 scan 做完整分析
                return false;
            }

            // JSON 块：检查括号平衡
            if (!isBalanced(scanRegion)) {
                Log.d(TAG, "isTruncated: unbalanced brackets in chunk");
                return true;
            }

            // 检查是否以正确终止标记结尾
            if (!endsWithTerminator(scanRegion)) {
                Log.d(TAG, "isTruncated: chunk does not end with valid terminator");
                return true;
            }

            // 尝试解析 JSON
            try {
                if (scanRegion.startsWith("{")) {
                    new JSONObject(scanRegion);
                } else {
                    new JSONArray(scanRegion);
                }
            } catch (JSONException e) {
                Log.d(TAG, "isTruncated: JSON parse failed in chunk: " + e.getMessage());
                return true;
            }

            return false;
        } catch (Exception e) {
            Log.e(TAG, "isTruncated: unexpected error during chunk detection", e);
            // 安全起见，检测异常时视为可能截断
            return true;
        }
    }

    /**
     * 对流式响应内容执行完整扫描，生成详细的截断检测报告。
     * <p>
     * 此方法执行全面的启发式分析，包括：
     * <ul>
     *   <li>JSON 解析验证顶层结构</li>
     *   <li>工具调用必需字段检查</li>
     *   <li>写工具内容长度检查</li>
     *   <li>括号平衡与终止标记检查</li>
     *   <li>字符串与字段边界截断检测</li>
     *   <li>流结束标记检查</li>
     * </ul>
     *
     * @param streamContent 完整的流式响应内容，可以为 null 或空
     * @return {@link ScanReport} 包含检测结果与详细信息，不会返回 null
     */
    public ScanReport scan(String streamContent) {
        ScanReportBuilder builder = new ScanReportBuilder(
                streamContent != null ? streamContent.length() : 0);

        if (streamContent == null || streamContent.trim().isEmpty()) {
            Log.w(TAG, "scan: stream content is null or empty");
            return builder
                    .addReason("stream_content_empty")
                    .build(1.0);
        }

        String trimmed = streamContent.trim();
        double score = 0.0;

        // 检查是否以 JSON 对象或数组开头
        boolean isJsonObject = trimmed.startsWith("{");
        boolean isJsonArray = trimmed.startsWith("[");

        if (!isJsonObject && !isJsonArray) {
            // 非 JSON 结构，检查截断信号
            if (detectUnclosedQuotes(trimmed)) {
                builder.addReason("unclosed_quotes_in_non_json");
                score += 0.3;
            }
            if (detectTruncatedField(trimmed)) {
                builder.addReason("truncated_field_in_non_json");
                score += 0.3;
            }
            if (trimmed.length() < MIN_WRITE_TOOL_CONTENT_LENGTH) {
                builder.addReason("content_too_short");
                score += 0.2;
            }
            return builder.build(score);
        }

        // ================================================================
        //  JSON 结构分析
        // ================================================================

        // 括号平衡检查
        if (!isBalanced(trimmed)) {
            builder.addReason("unbalanced_brackets");
            score += 0.4;
        }

        // 终止标记检查
        if (!endsWithTerminator(trimmed)) {
            builder.addReason("missing_stream_terminator");
            score += 0.2;
        }

        // 字符串截断检测
        if (detectUnclosedQuotes(trimmed)) {
            builder.addReason("unclosed_string_value");
            score += 0.3;
        }

        // 字段名截断检测
        if (detectTruncatedField(trimmed)) {
            builder.addReason("truncated_field_name");
            score += 0.3;
        }

        // 未闭合的括号/花括号检测
        if (detectUnclosedBracket(trimmed)) {
            builder.addReason("unclosed_bracket_or_brace");
            score += 0.3;
        }

        // ================================================================
        //  JSON 解析验证
        // ================================================================

        try {
            if (isJsonObject) {
                JSONObject json = new JSONObject(trimmed);
                score += analyzeJsonObject(json, builder);
            } else {
                JSONArray json = new JSONArray(trimmed);
                score += analyzeJsonArray(json, builder);
            }
        } catch (JSONException e) {
            builder.addReason("json_parse_error: " + e.getMessage());
            builder.addError(e);
            score += 0.5;
            Log.d(TAG, "scan: JSON parse error: " + e.getMessage());
        }

        return builder.build(score);
    }

    /**
     * 计算内容截断的置信度分数。
     * <p>
     * 返回 0.0（完全正常）到 1.0（确定截断）之间的分数。
     * 此方法执行与 {@link #scan(String)} 相同的分析，但仅返回聚合分数。
     *
     * @param content 需要评估的内容，可以为 null 或空
     * @return 截断置信度分数（0.0 ~ 1.0）
     */
    public double getTruncationScore(String content) {
        if (content == null || content.trim().isEmpty()) {
            return 1.0;
        }
        ScanReport report = scan(content);
        return report.score;
    }

    // ================================================================
    //  JSON 分析
    // ================================================================

    /**
     * 分析 JSON 对象的截断可能性。
     *
     * @param json    JSON 对象
     * @param builder 报告构建器
     * @return 该部分贡献的分数增量
     */
    private double analyzeJsonObject(JSONObject json, ScanReportBuilder builder) {
        double score = 0.0;

        // 检查是否为空对象
        if (json.length() == 0) {
            builder.addReason("empty_json_object");
            score += 0.2;
            return score;
        }

        // 检查必需字段
        List<String> missingFields = checkRequiredFields(json);
        if (!missingFields.isEmpty()) {
            builder.addReason("missing_required_fields: " + String.join(", ", missingFields));
            score += 0.3;
        }

        // 检测工具调用
        if (json.has("name") || json.has("tool")) {
            score += analyzeToolCall(json, builder);
        }

        // 递归检查嵌套对象
        for (String key : json.keySet()) {
            try {
                Object value = json.get(key);
                if (value instanceof JSONObject) {
                    score += analyzeJsonObject((JSONObject) value, builder);
                } else if (value instanceof JSONArray) {
                    score += analyzeJsonArray((JSONArray) value, builder);
                }
            } catch (JSONException e) {
                // 忽略，继续检查其他字段
                Log.v(TAG, "analyzeJsonObject: skipping key " + key + ": " + e.getMessage());
            }
        }

        return score;
    }

    /**
     * 分析 JSON 数组的截断可能性。
     *
     * @param json    JSON 数组
     * @param builder 报告构建器
     * @return 该部分贡献的分数增量
     */
    private double analyzeJsonArray(JSONArray json, ScanReportBuilder builder) {
        double score = 0.0;

        // 检查为空数组
        if (json.length() == 0) {
            builder.addReason("empty_json_array");
            score += 0.1;
            return score;
        }

        // 遍历数组元素
        for (int i = 0; i < json.length(); i++) {
            try {
                Object value = json.get(i);
                if (value instanceof JSONObject) {
                    score += analyzeJsonObject((JSONObject) value, builder);
                } else if (value instanceof JSONArray) {
                    score += analyzeJsonArray((JSONArray) value, builder);
                }
            } catch (JSONException e) {
                builder.addReason("array_element_parse_error_at_index_" + i);
                builder.addError(e);
                score += 0.2;
                Log.v(TAG, "analyzeJsonArray: error at index " + i + ": " + e.getMessage());
            }
        }

        return score;
    }

    // ================================================================
    //  工具调用分析
    // ================================================================

    /**
     * 分析工具调用 JSON 的截断可能性。
     * <p>
     * 检查工具名称是否包含写工具关键词，以及 content/input 字段
     * 的长度是否合理。
     *
     * @param json    工具调用 JSON 对象
     * @param builder 报告构建器
     * @return 该部分贡献的分数增量
     */
    private double analyzeToolCall(JSONObject json, ScanReportBuilder builder) {
        double score = 0.0;

        String toolName = json.optString("name", "");
        if (toolName.isEmpty()) {
            toolName = json.optString("tool", "");
        }

        if (toolName.isEmpty()) {
            return score;
        }

        boolean isWriteTool = isWriteTool(toolName);
        if (!isWriteTool) {
            return score;
        }

        // 检查写工具的 content 或 input 字段长度
        String content = json.optString("content", "");
        if (content.isEmpty()) {
            content = json.optString("input", "");
        }
        if (content.isEmpty()) {
            // 尝试从 arguments 中提取 content
            JSONObject arguments = json.optJSONObject("arguments");
            if (arguments != null) {
                content = arguments.optString("content", "");
                if (content.isEmpty()) {
                    content = arguments.optString("input", "");
                }
                if (content.isEmpty()) {
                    content = arguments.optString("text", "");
                }
                if (content.isEmpty()) {
                    content = arguments.optString("code", "");
                }
            }
        }

        if (content.isEmpty()) {
            builder.addReason("write_tool_missing_content: " + toolName);
            score += 0.4;
        } else if (content.length() < MIN_WRITE_TOOL_CONTENT_LENGTH) {
            builder.addReason("write_tool_content_too_short: " + toolName
                    + " (" + content.length() + " chars)");
            score += 0.3;
        }

        // 检查 arguments 字段是否为空
        JSONObject args = json.optJSONObject("arguments");
        if (args != null && args.length() == 0) {
            builder.addReason("write_tool_empty_arguments: " + toolName);
            score += 0.2;
        }

        return score;
    }

    // ================================================================
    //  辅助检测方法
    // ================================================================

    /**
     * 检查括号（{}, [], ()）是否平衡。
     *
     * @param content 要检查的内容
     * @return true 如果所有括号都平衡
     */
    private boolean isBalanced(String content) {
        int braceCount = 0;   // {}
        int bracketCount = 0; // []
        boolean inString = false;
        char prevChar = 0;

        for (int i = 0; i < content.length(); i++) {
            char c = content.charAt(i);

            if (c == '"' && prevChar != '\\') {
                inString = !inString;
            }

            if (!inString) {
                switch (c) {
                    case '{':
                        braceCount++;
                        break;
                    case '}':
                        braceCount--;
                        break;
                    case '[':
                        bracketCount++;
                        break;
                    case ']':
                        bracketCount--;
                        break;
                    default:
                        break;
                }
            }
            prevChar = c;
        }

        return braceCount == 0 && bracketCount == 0;
    }

    /**
     * 检查内容是否以有效的流终止标记结尾。
     *
     * @param content 要检查的内容
     * @return true 如果以终止标记结尾
     */
    private boolean endsWithTerminator(String content) {
        if (content == null || content.isEmpty()) {
            return false;
        }

        // 跳过末尾空白
        int end = content.length() - 1;
        while (end >= 0 && Character.isWhitespace(content.charAt(end))) {
            end--;
        }
        if (end < 0) {
            return false;
        }

        char lastChar = content.charAt(end);
        for (char terminator : STREAM_TERMINATORS) {
            if (lastChar == terminator) {
                return true;
            }
        }
        return false;
    }

    /**
     * 检测内容中是否存在未闭合的引号字符串。
     *
     * @param content 要检查的内容
     * @return true 如果存在未闭合的引号
     */
    private boolean detectUnclosedQuotes(String content) {
        Matcher matcher = TRUNCATED_STRING_PATTERN.matcher(content);
        if (matcher.find()) {
            String match = matcher.group();
            // 如果引号是最后一个字符且前面有冒号，说明值是截断的
            if (match.endsWith("\"") && match.length() > 1) {
                return false; // 正常闭合
            }
            // 检查是否是未闭合的字符串（引号后没有内容）
            Matcher unclosedMatcher = UNCLOSED_STRING_PATTERN.matcher(content);
            return unclosedMatcher.find();
        }
        return false;
    }

    /**
     * 检测内容中是否存在截断的字段名（不完整的 JSON 键）。
     *
     * @param content 要检查的内容
     * @return true 如果存在截断的字段名
     */
    private boolean detectTruncatedField(String content) {
        Matcher matcher = TRUNCATED_FIELD_PATTERN.matcher(content);
        if (matcher.find()) {
            String match = matcher.group();
            // 如果末尾是引号，字段名可能是完整的
            if (match.endsWith("\"")) {
                // 检查引号后是否有冒号
                int endIdx = content.indexOf(match) + match.length();
                if (endIdx < content.length() && content.charAt(endIdx) == ':') {
                    // 引号后有冒号，说明字段名完整
                    if (endIdx + 1 < content.length()) {
                        char afterColon = content.charAt(endIdx + 1);
                        return afterColon != '"' && afterColon != '{' && afterColon != '['
                                && !Character.isDigit(afterColon) && afterColon != 't'
                                && afterColon != 'f' && afterColon != 'n';
                    }
                    return true; // 冒号后没有内容
                }
                return false; // 完整的字段名，但可能后面没内容不算截断
            }
            // 以字母/数字结尾但无引号，说明字段名被截断
            return true;
        }
        return false;
    }

    /**
     * 检测内容中是否存在未闭合的括号或花括号。
     *
     * @param content 要检查的内容
     * @return true 如果存在未闭合的括号
     */
    private boolean detectUnclosedBracket(String content) {
        Matcher matcher = UNCLOSED_BRACKET_PATTERN.matcher(content);
        return matcher.find();
    }

    /**
     * 检查 JSON 对象是否包含所有必需字段。
     *
     * @param json JSON 对象
     * @return 缺失的必需字段列表，如果全部存在则返回空列表
     */
    private List<String> checkRequiredFields(JSONObject json) {
        List<String> missing = new ArrayList<>();
        for (String field : REQUIRED_TOOL_FIELDS) {
            if (!json.has(field)) {
                missing.add(field);
            }
        }
        return missing;
    }

    /**
     * 判断工具名称是否为写工具（write/create/update 等）。
     *
     * @param toolName 工具名称
     * @return true 如果工具是写工具
     */
    private boolean isWriteTool(String toolName) {
        if (toolName == null || toolName.isEmpty()) {
            return false;
        }
        String lower = toolName.toLowerCase();
        for (String keyword : WRITE_TOOL_KEYWORDS) {
            if (lower.contains(keyword)) {
                return true;
            }
        }
        return false;
    }

    // ================================================================
    //  辅助方法
    // ================================================================

    /**
     * 判断响应是否可以被安全忽略（空响应或心跳）。
     * <p>
     * 空响应、只有空白字符的响应、以及仅包含心跳标记（如 {@code [DONE]}）
     * 的响应不被视为截断。
     *
     * @param response 响应字符串
     * @return true 如果响应可以被安全忽略
     */
    public boolean isIgnorable(String response) {
        if (response == null) {
            return true;
        }
        String trimmed = response.trim();
        return trimmed.isEmpty() || "[DONE]".equals(trimmed)
                || "[]".equals(trimmed) || "{}".equals(trimmed);
    }
}