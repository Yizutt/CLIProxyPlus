package com.cliproxy.plus.proxy.translation;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.Map;

/**
 * FormatTranslator - AI API 协议格式转换器接口
 * <p>
 * 定义不同 AI API 协议格式之间的转换契约。
 * 每个实现类负责将请求从一种协议格式（如 Claude、Gemini、Codex、Antigravity）
 * 转换为另一种协议格式（如 OpenAI），并相应处理响应。
 * </p>
 *
 * <h3>支持的协议格式</h3>
 * <ul>
 *   <li>OpenAI - /v1/chat/completions 格式</li>
 *   <li>Claude - /v1/messages 格式（Anthropic）</li>
 *   <li>Gemini - /v1beta 格式（Google）</li>
 *   <li>Codex - /backend-api/codex 格式（OpenAI Codex）</li>
 *   <li>Antigravity - 反重力协议格式（自定义）</li>
 * </ul>
 *
 * <h3>转换流程</h3>
 * <pre>
 * 上游请求 (Claude/Gemini/Codex/...)
 *       │
 *       ▼
 *  FormatTranslator.translate(request, headers)
 *       │
 *       ▼
 *  OpenAI 兼容请求 (转发到后端)
 *       │
 *       ▼
 *  OpenAI 兼容响应 (从后端返回)
 *       │
 *       ▼
 *  FormatTranslator.translateResponse(response, headers)
 *       │
 *       ▼
 * 上游格式响应 (返回给客户端)
 * </pre>
 *
 * 对应原版 internal/api/translator/translator.go
 *
 * @author CLIProxy Plus Team
 * @version 1.0.0
 */
public interface FormatTranslator {

    /**
     * TAG - Android Log 标签，用于日志输出
     * 子类应使用各自实现类的名称作为 TAG
     */
    String TAG = "FormatTranslator";

    /**
     * 将请求 JSON 从源协议格式转换为目标协议格式
     * <p>
     * 执行字段映射、模型名称转换、消息格式调整等操作。
     * 转换过程中产生的异常应包装为 {@link TranslationException} 抛出。
     * </p>
     *
     * <h3>典型转换流程</h3>
     * <ol>
     *   <li>解析源格式 JSON</li>
     *   <li>映射模型名称（如 claude-sonnet-4 → gpt-4-turbo）</li>
     *   <li>转换消息结构（合并 system prompt、处理多模态内容）</li>
     *   <li>映射参数（如 stop_sequences → stop、thinking → reasoning_effort）</li>
     *   <li>构建目标格式 JSON 并返回</li>
     * </ol>
     *
     * @param sourceJson 源协议格式的请求体 JSON 字符串
     * @param headers    请求头信息，包含鉴权、内容类型等元数据
     * @return 目标协议格式的请求体 JSON 字符串
     * @throws TranslationException 转换过程中发生错误时抛出
     */
    String translate(String sourceJson, Map<String, String> headers) throws TranslationException;

    /**
     * TranslationException - 协议格式转换异常
     * <p>
     * 在格式转换过程中发生错误时抛出的受检异常。
     * 包含错误代码和详细描述，用于上层调用方进行错误处理和日志记录。
     * </p>
     *
     * <h3>使用场景</h3>
     * <ul>
     *   <li>JSON 解析失败（格式错误、字段缺失、类型不匹配）</li>
     *   <li>模型名称映射失败（未知或不支持的模型）</li>
     *   <li>消息结构转换失败（不支持的 content 类型）</li>
     *   <li>参数映射失败（不支持的参数组合）</li>
     *   <li>协议版本不兼容（缺少必要字段）</li>
     * </ul>
     *
     * 对应原版 internal/api/translator/translator.go 中的 TranslationError
     */
    class TranslationException extends Exception {

        /**
         * 错误代码：未知错误
         */
        public static final int ERROR_UNKNOWN = 0;

        /**
         * 错误代码：JSON 解析失败
         */
        public static final int ERROR_PARSE = 1;

        /**
         * 错误代码：模型映射失败
         */
        public static final int ERROR_MODEL_MAPPING = 2;

        /**
         * 错误代码：消息结构转换失败
         */
        public static final int ERROR_MESSAGE_CONVERSION = 3;

        /**
         * 错误代码：参数映射失败
         */
        public static final int ERROR_PARAMETER_MAPPING = 4;

        /**
         * 错误代码：不支持的协议版本
         */
        public static final int ERROR_UNSUPPORTED_VERSION = 5;

        /**
         * 错误代码：请求体为空
         */
        public static final int ERROR_EMPTY_BODY = 6;

        /**
         * 错误代码：缺少必要字段
         */
        public static final int ERROR_MISSING_FIELD = 7;

        /**
         * 错误代码：不支持的协议格式
         */
        public static final int ERROR_UNSUPPORTED_FORMAT = 8;

        /**
         * 错误代码：流式响应转换失败
         */
        public static final int ERROR_STREAM_CONVERSION = 9;

        /**
         * 错误代码
         */
        private final int errorCode;

        /**
         * 构造一个带错误消息的 TranslationException
         *
         * @param message 错误描述信息
         */
        public TranslationException(String message) {
            super(message);
            this.errorCode = ERROR_UNKNOWN;
            Log.w(TAG, "TranslationException: [" + ERROR_UNKNOWN + "] " + message);
        }

        /**
         * 构造一个带错误代码和错误消息的 TranslationException
         *
         * @param errorCode 错误代码，使用本类中定义的 {@code ERROR_*} 常量
         * @param message   错误描述信息
         */
        public TranslationException(int errorCode, String message) {
            super(message);
            this.errorCode = errorCode;
            Log.w(TAG, "TranslationException: [" + errorCode + "] " + message);
        }

        /**
         * 构造一个带错误消息和原始原因的 TranslationException
         *
         * @param message 错误描述信息
         * @param cause   原始异常原因
         */
        public TranslationException(String message, Throwable cause) {
            super(message, cause);
            this.errorCode = ERROR_UNKNOWN;
            Log.w(TAG, "TranslationException: [" + ERROR_UNKNOWN + "] " + message, cause);
        }

        /**
         * 构造一个带错误代码、错误消息和原始原因的 TranslationException
         *
         * @param errorCode 错误代码，使用本类中定义的 {@code ERROR_*} 常量
         * @param message   错误描述信息
         * @param cause     原始异常原因
         */
        public TranslationException(int errorCode, String message, Throwable cause) {
            super(message, cause);
            this.errorCode = errorCode;
            Log.w(TAG, "TranslationException: [" + errorCode + "] " + message, cause);
        }

        /**
         * 获取错误代码
         *
         * @return 错误代码，值为本类中定义的 {@code ERROR_*} 常量之一
         */
        public int getErrorCode() {
            return errorCode;
        }

        /**
         * 返回异常的错误代码和描述信息
         *
         * @return 格式为 "[errorCode] message" 的字符串
         */
        @Override
        public String toString() {
            return "[" + errorCode + "] " + getMessage();
        }
    }
}