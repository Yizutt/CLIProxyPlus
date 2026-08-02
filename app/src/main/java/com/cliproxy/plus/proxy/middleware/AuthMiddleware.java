package com.cliproxy.plus.proxy.middleware;

import android.util.Log;

import java.util.List;
import java.util.Map;

/**
 * AuthMiddleware - API Key 认证中间件
 * 验证客户端请求中的 Authorization header
 * 对应原版 internal/api/middleware/
 */
public class AuthMiddleware {

    private static final String TAG = "AuthMiddleware";

    /**
     * 验证请求认证
     * @param headers 请求头
     * @param apiKeys 允许的 API Key 列表
     * @return true 如果认证通过
     */
    public boolean authenticate(Map<String, String> headers, List<String> apiKeys) {
        // 如果未配置 API Key，允许所有请求（兼容模式）
        if (apiKeys == null || apiKeys.isEmpty()) {
            return true;
        }

        String authHeader = headers.get("authorization");
        if (authHeader == null) {
            authHeader = headers.get("Authorization");
        }

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            Log.w(TAG, "Missing or invalid Authorization header");
            return false;
        }

        String token = authHeader.substring(7).trim();
        for (String apiKey : apiKeys) {
            if (apiKey.equals(token)) {
                return true;
            }
        }

        Log.w(TAG, "Invalid API key: " + token.substring(0, Math.min(8, token.length())) + "...");
        return false;
    }

    /**
     * 验证管理 API 密钥
     */
    public boolean authenticateManagement(Map<String, String> headers, String secretKey) {
        if (secretKey == null || secretKey.isEmpty()) {
            return false;
        }

        String authHeader = headers.get("authorization");
        if (authHeader == null) {
            authHeader = headers.get("Authorization");
        }

        // 支持 Bearer 和 X-Management-Key 两种方式
        if (authHeader != null) {
            if (authHeader.startsWith("Bearer ")) {
                return secretKey.equals(authHeader.substring(7).trim());
            }
            return secretKey.equals(authHeader.trim());
        }

        String mgmtKey = headers.get("X-Management-Key");
        if (mgmtKey != null) {
            return secretKey.equals(mgmtKey.trim());
        }

        return false;
    }
}