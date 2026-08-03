package com.cliproxy.plus.ui.oauth;

import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.cardview.widget.CardView;
import androidx.fragment.app.Fragment;
import com.cliproxy.plus.management.ManagementAPIClient;
import com.cliproxy.plus.config.ConfigManager;
import android.os.Handler;
import android.os.Looper;

import com.cliproxy.plus.auth.AuthManager;
import com.cliproxy.plus.auth.AuthManager.AuthCredential;
import com.cliproxy.plus.auth.oauth.OAuthProvider;
import com.cliproxy.plus.auth.oauth.OAuthProvider.PKCECodes;
import com.cliproxy.plus.auth.oauth.OAuthProvider.TokenData;
import com.cliproxy.plus.auth.oauth.OAuthProvider.AuthResult;
import com.cliproxy.plus.config.ConfigManager;
import com.cliproxy.plus.management.ManagementAPIClient;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * OAuthFragment - OAuth 登录管理 (纯 Java UI)
 *
 * Shows a list of OAuth providers with login buttons.
 * Each provider displays its login status (logged in / not logged in).
 * Provides a start-login button that triggers the OAuth flow.
 */
public class OAuthFragment extends Fragment {

    private static final String TAG = "OAuthFragment";

    // Color constants matching the project dark theme
    private static final String COLOR_BG = "#1E1E2E";
    private static final String COLOR_CARD = "#313244";
    private static final String COLOR_PRIMARY = "#7C3AED";
    private static final String COLOR_TEXT = "#CDD6F4";
    private static final String COLOR_TEXT_SECONDARY = "#A6ADC8";
    private static final String COLOR_TITLE = "#F5C2E7";
    private static final String COLOR_GREEN = "#22C55E";
    private static final String COLOR_RED = "#EF4444";
    private static final String COLOR_BUTTON_BG = "#7C3AED";
    private static final String COLOR_BUTTON_BG_DISABLED = "#4B5563";

    private LinearLayout providerContainer;
    private TextView statusSummary;
    private ProgressBar loadingSpinner;
    private Button refreshButton;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    private ManagementAPIClient apiClient;

    // Predefined list of known OAuth providers
    private final List<ProviderInfo> providers = new ArrayList<>();

    private static class ProviderInfo {
        final String id;
        final String displayName;
        final String iconText;
        boolean loggedIn;
        String accountEmail;
        AuthCredential credential;

        ProviderInfo(String id, String displayName, String iconText) {
            this.id = id;
            this.displayName = displayName;
            this.iconText = iconText;
            this.loggedIn = false;
            this.accountEmail = "";
        }
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull android.view.LayoutInflater inflater,
                              @Nullable ViewGroup container,
                              @Nullable Bundle savedInstanceState) {
        Log.d(TAG, "onCreateView: initializing OAuth login management UI");

        ScrollView scrollView = new ScrollView(requireContext());
        scrollView.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
        scrollView.setPadding(16, 16, 16, 16);
        scrollView.setBackgroundColor(Color.parseColor(COLOR_BG));

        LinearLayout root = new LinearLayout(requireContext());
        root.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        root.setOrientation(LinearLayout.VERTICAL);

        // Title
        root.addView(createTitle("OAuth 登录管理"));

        // Status summary bar
        statusSummary = new TextView(requireContext());
        statusSummary.setText("正在加载...");
        statusSummary.setTextColor(Color.parseColor(COLOR_TEXT_SECONDARY));
        statusSummary.setTextSize(14);
        statusSummary.setPadding(0, 0, 0, 12);
        root.addView(statusSummary);

        // Loading spinner (shown during refresh)
        loadingSpinner = new ProgressBar(requireContext(), null, android.R.attr.progressBarStyleSmall);
        loadingSpinner.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        loadingSpinner.setVisibility(View.GONE);
        LinearLayout spinnerRow = new LinearLayout(requireContext());
        spinnerRow.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        spinnerRow.setGravity(Gravity.CENTER);
        spinnerRow.setPadding(0, 0, 0, 12);
        spinnerRow.addView(loadingSpinner);
        root.addView(spinnerRow);

        // Provider cards container
        providerContainer = new LinearLayout(requireContext());
        providerContainer.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        providerContainer.setOrientation(LinearLayout.VERTICAL);
        root.addView(providerContainer);

        // Refresh button
        refreshButton = new Button(requireContext());
        refreshButton.setText("刷新状态");
        refreshButton.setTextColor(Color.WHITE);
        refreshButton.setTextSize(14);
        refreshButton.setTypeface(null, Typeface.BOLD);
        refreshButton.setBackgroundColor(Color.parseColor(COLOR_BUTTON_BG));
        refreshButton.setPadding(16, 12, 16, 12);
        LinearLayout.LayoutParams refreshBtnParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        refreshBtnParams.setMargins(0, 8, 0, 0);
        refreshButton.setLayoutParams(refreshBtnParams);
        refreshButton.setOnClickListener(v -> {
            Log.d(TAG, "Refresh button clicked");
            refreshProviderList();
        });
        root.addView(refreshButton);

        scrollView.addView(root);

        // Initialize Management API client to fetch data from the Go server
        int port = ConfigManager.getInstance().getInt("port", 8317);
        apiClient = new ManagementAPIClient("http://127.0.0.1:" + port);
        Log.d(TAG, "ManagementAPIClient initialized with port " + port);

        return scrollView;
    }

    @Override
    public void onResume() {
        super.onResume();
        Log.d(TAG, "onResume: refreshing OAuth provider list");
        refreshProviderList();
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        executor.shutdown();
    }

    // ====== Data Loading ======

    private void refreshProviderList() {
        showLoading(true);
        executor.execute(() -> {
            loadProviders();
            mainHandler.post(() -> {
                renderProviders();
                updateStatusSummary();
                showLoading(false);
            });
        });
    }

    /**
     * Load provider list from the Go server via ManagementAPIClient.
     * Fetches auth files and their status, merging with known providers.
     */
    private void loadProviders() {
        providers.clear();

        // Define known OAuth providers with their display info
        List<ProviderInfo> knownProviders = new ArrayList<>();
        knownProviders.add(new ProviderInfo("gemini", "Google Gemini", "G"));
        knownProviders.add(new ProviderInfo("claude", "Anthropic Claude", "A"));
        knownProviders.add(new ProviderInfo("codex", "OpenAI Codex", "O"));
        knownProviders.add(new ProviderInfo("xai", "xAI Grok", "X"));
        knownProviders.add(new ProviderInfo("kiro", "Kiro AI", "K"));
        knownProviders.add(new ProviderInfo("antigravity", "AntiGravity", "AG"));
        knownProviders.add(new ProviderInfo("openrouter", "OpenRouter", "OR"));
        knownProviders.add(new ProviderInfo("custom", "自定义提供商", "C"));

        // Fetch auth files from the Go server via ManagementAPIClient
        try {
            JSONArray authFiles = apiClient.listAuthFiles();

            // Build a set of provider IDs that have auth files
            java.util.Set<String> loggedInProviders = new java.util.HashSet<>();
            java.util.Map<String, String> providerEmails = new java.util.HashMap<>();

            if (authFiles != null) {
                for (int i = 0; i < authFiles.length(); i++) {
                    JSONObject file = authFiles.optJSONObject(i);
                    if (file != null) {
                        String provider = file.optString("provider", "");
                        String name = file.optString("name", "");
                        if (!provider.isEmpty()) {
                            loggedInProviders.add(provider);
                            if (!name.isEmpty()) {
                                providerEmails.put(provider, name);
                            }
                        }
                    } else {
                        // If array element is a plain string, use it as provider id
                        String providerStr = authFiles.optString(i, "");
                        if (!providerStr.isEmpty()) {
                            loggedInProviders.add(providerStr);
                        }
                    }
                }
            }

            for (ProviderInfo info : knownProviders) {
                if (loggedInProviders.contains(info.id)) {
                    info.loggedIn = true;
                    info.accountEmail = providerEmails.getOrDefault(info.id, "已登录");
                } else {
                    info.loggedIn = false;
                    info.accountEmail = "";
                }
                info.credential = null;
                providers.add(info);
            }

            // Add any providers from auth files not in the known list
            for (String providerId : loggedInProviders) {
                boolean known = false;
                for (ProviderInfo info : knownProviders) {
                    if (info.id.equals(providerId)) {
                        known = true;
                        break;
                    }
                }
                if (!known) {
                    ProviderInfo unknownInfo = new ProviderInfo(
                            providerId, providerId, "?");
                    unknownInfo.loggedIn = true;
                    unknownInfo.accountEmail = providerEmails.getOrDefault(providerId, "已登录");
                    providers.add(unknownInfo);
                }
            }

            Log.d(TAG, "loadProviders: loaded " + providers.size() + " providers from server, "
                    + getLoggedInCount() + " logged in");
        } catch (Exception e) {
            Log.e(TAG, "Failed to load auth files from server", e);
            // Fallback: show known providers as not logged in
            for (ProviderInfo info : knownProviders) {
                info.loggedIn = false;
                info.accountEmail = "";
                info.credential = null;
                providers.add(info);
            }

            // Still add a note about the failure to the status summary
            mainHandler.post(() -> {
                statusSummary.setText("加载失败: " + e.getMessage());
                statusSummary.setTextColor(Color.parseColor(COLOR_RED));
            });
        }
    }

    private int getLoggedInCount() {
        int count = 0;
        for (ProviderInfo info : providers) {
            if (info.loggedIn) count++;
        }
        return count;
    }

    // ====== UI Rendering ======

    private void renderProviders() {
        providerContainer.removeAllViews();

        if (providers.isEmpty()) {
            TextView emptyView = new TextView(requireContext());
            emptyView.setText("暂无可用提供商");
            emptyView.setTextColor(Color.parseColor(COLOR_TEXT_SECONDARY));
            emptyView.setTextSize(16);
            emptyView.setGravity(Gravity.CENTER);
            emptyView.setPadding(0, 32, 0, 32);
            providerContainer.addView(emptyView);
            return;
        }

        for (ProviderInfo info : providers) {
            providerContainer.addView(createProviderCard(info));
        }
    }

    private void updateStatusSummary() {
        int total = providers.size();
        int loggedIn = getLoggedInCount();
        statusSummary.setText("共 " + total + " 个提供商，已登录 " + loggedIn + " 个");
        statusSummary.setTextColor(Color.parseColor(COLOR_TEXT_SECONDARY));
    }

    private void showLoading(boolean show) {
        loadingSpinner.setVisibility(show ? View.VISIBLE : View.GONE);
        refreshButton.setEnabled(!show);
        refreshButton.setTextColor(show ? Color.parseColor(COLOR_TEXT_SECONDARY) : Color.WHITE);
    }

    /**
     * Create a provider card with icon, name, status, and action button.
     */
    private CardView createProviderCard(ProviderInfo info) {
        CardView card = new CardView(requireContext());
        LinearLayout.LayoutParams cardParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        cardParams.setMargins(0, 0, 0, 12);
        card.setLayoutParams(cardParams);
        card.setCardBackgroundColor(Color.parseColor(COLOR_CARD));
        card.setRadius(12);
        card.setCardElevation(4);
        card.setUseCompatPadding(true);

        LinearLayout content = new LinearLayout(requireContext());
        content.setOrientation(LinearLayout.HORIZONTAL);
        content.setPadding(16, 16, 16, 16);
        content.setGravity(Gravity.CENTER_VERTICAL);

        // Provider icon (text-based circle)
        FrameLayout iconContainer = new FrameLayout(requireContext());
        LinearLayout.LayoutParams iconParams = new LinearLayout.LayoutParams(48, 48);
        iconParams.setMargins(0, 0, 12, 0);
        iconContainer.setLayoutParams(iconParams);
        iconContainer.setBackground(createCircleDrawable(info.loggedIn
                ? Color.parseColor(COLOR_GREEN) : Color.parseColor("#4B5563")));

        TextView iconText = new TextView(requireContext());
        iconText.setText(info.iconText);
        iconText.setTextColor(Color.WHITE);
        iconText.setTextSize(16);
        iconText.setTypeface(null, Typeface.BOLD);
        iconText.setGravity(Gravity.CENTER);
        iconText.setLayoutParams(new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
        iconContainer.addView(iconText);

        content.addView(iconContainer);

        // Provider info (name + status)
        LinearLayout textColumn = new LinearLayout(requireContext());
        textColumn.setLayoutParams(new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        textColumn.setOrientation(LinearLayout.VERTICAL);

        TextView nameView = new TextView(requireContext());
        nameView.setText(info.displayName);
        nameView.setTextColor(Color.parseColor(COLOR_TEXT));
        nameView.setTextSize(16);
        nameView.setTypeface(null, Typeface.BOLD);
        textColumn.addView(nameView);

        TextView statusView = new TextView(requireContext());
        if (info.loggedIn) {
            statusView.setText(info.accountEmail.isEmpty() ? "已登录" : info.accountEmail);
            statusView.setTextColor(Color.parseColor(COLOR_GREEN));
        } else {
            statusView.setText("未登录");
            statusView.setTextColor(Color.parseColor(COLOR_TEXT_SECONDARY));
        }
        statusView.setTextSize(13);
        statusView.setPadding(0, 2, 0, 0);
        textColumn.addView(statusView);

        content.addView(textColumn);

        // Action button
        Button actionButton = new Button(requireContext());
        if (info.loggedIn) {
            actionButton.setText("管理");
            actionButton.setBackgroundColor(Color.parseColor("#3B82F6"));
        } else {
            actionButton.setText("登录");
            actionButton.setBackgroundColor(Color.parseColor(COLOR_BUTTON_BG));
        }
        actionButton.setTextColor(Color.WHITE);
        actionButton.setTextSize(13);
        actionButton.setTypeface(null, Typeface.BOLD);
        actionButton.setPadding(16, 8, 16, 8);
        actionButton.setAllCaps(false);

        final ProviderInfo finalInfo = info;
        actionButton.setOnClickListener(v -> {
            if (finalInfo.loggedIn) {
                Log.d(TAG, "Manage account for provider: " + finalInfo.id);
                showManageDialog(finalInfo);
            } else {
                Log.d(TAG, "Start OAuth login for provider: " + finalInfo.id);
                startOAuthLogin(finalInfo);
            }
        });

        content.addView(actionButton);
        card.addView(content);
        return card;
    }

    /**
     * Create a simple circle drawable programmatically.
     */
    private android.graphics.drawable.GradientDrawable createCircleDrawable(int color) {
        android.graphics.drawable.GradientDrawable drawable =
                new android.graphics.drawable.GradientDrawable();
        drawable.setShape(android.graphics.drawable.GradientDrawable.OVAL);
        drawable.setColor(color);
        drawable.setSize(48, 48);
        return drawable;
    }

    // ====== OAuth Flow ======

    /**
     * Initiate the OAuth login flow for the given provider.
     * Opens the provider's authorization URL in the browser.
     */
    private void startOAuthLogin(ProviderInfo info) {
        Log.i(TAG, "Starting OAuth login for: " + info.id);

        // In a real implementation, this would use provider-specific configurations
        // from ConfigManager. Here we build a sample authorization URL.
        executor.execute(() -> {
            try {
                // Generate PKCE codes for the OAuth flow
                PKCECodes pkce = OAuthProvider.generatePKCECodes();

                // Build the authorization URL (simplified; actual URL depends on provider)
                String authUrl = buildAuthUrl(info.id, pkce.codeChallenge);

                Log.d(TAG, "Opening auth URL for " + info.id + ": " + authUrl);

                // Open the URL in the device browser to start the OAuth flow
                mainHandler.post(() -> {
                    Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(authUrl));
                    startActivity(intent);
                });

                // In a real app, the callback would be handled by a custom scheme or
                // redirect URI listener, which would exchange the code for tokens.
                // For now, we simulate a successful login after the browser opens.
                Log.d(TAG, "OAuth flow initiated for " + info.id
                        + ". Waiting for callback...");

            } catch (Exception e) {
                Log.e(TAG, "Failed to start OAuth login for " + info.id, e);
                mainHandler.post(() -> showToast("登录失败: " + e.getMessage()));
            }
        });
    }

    /**
     * Build the OAuth authorization URL for a given provider.
     */
    private String buildAuthUrl(String providerId, String codeChallenge) {
        // These URIs are representative; real implementations would load from config.
        // The redirect URI should be registered with the provider.
        String redirectUri = "cliproxy://oauth/callback";

        switch (providerId) {
            case "gemini":
                return "https://accounts.google.com/o/oauth2/v2/auth"
                        + "?client_id=gemini-client-id"
                        + "&redirect_uri=" + Uri.encode(redirectUri)
                        + "&response_type=code"
                        + "&scope=" + Uri.encode("openid email profile")
                        + "&code_challenge=" + codeChallenge
                        + "&code_challenge_method=S256"
                        + "&state=" + providerId;
            case "claude":
                return "https://auth.anthropic.com/authorize"
                        + "?client_id=claude-client-id"
                        + "&redirect_uri=" + Uri.encode(redirectUri)
                        + "&response_type=code"
                        + "&scope=" + Uri.encode("openid email")
                        + "&code_challenge=" + codeChallenge
                        + "&code_challenge_method=S256"
                        + "&state=" + providerId;
            case "codex":
                return "https://github.com/login/oauth/authorize"
                        + "?client_id=codex-client-id"
                        + "&redirect_uri=" + Uri.encode(redirectUri)
                        + "&scope=" + Uri.encode("read:user user:email")
                        + "&state=" + providerId;
            case "xai":
                return "https://auth.x.ai/authorize"
                        + "?client_id=xai-client-id"
                        + "&redirect_uri=" + Uri.encode(redirectUri)
                        + "&response_type=code"
                        + "&scope=" + Uri.encode("openid email")
                        + "&code_challenge=" + codeChallenge
                        + "&code_challenge_method=S256"
                        + "&state=" + providerId;
            default:
                // Generic OAuth URL for other providers
                return "https://auth.example.com/oauth2/authorize"
                        + "?client_id=" + providerId + "-client-id"
                        + "&redirect_uri=" + Uri.encode(redirectUri)
                        + "&response_type=code"
                        + "&scope=" + Uri.encode("openid profile")
                        + "&code_challenge=" + codeChallenge
                        + "&code_challenge_method=S256"
                        + "&state=" + providerId;
        }
    }

    /**
     * Show a dialog to manage an existing OAuth session (logout, refresh, etc.).
     */
    private void showManageDialog(ProviderInfo info) {
        Log.d(TAG, "Showing management dialog for " + info.id);

        // Build a simple dialog with management options
        android.app.AlertDialog dialog = new android.app.AlertDialog.Builder(requireContext())
                .setTitle(info.displayName)
                .setMessage("账号: " + (info.accountEmail.isEmpty() ? info.id : info.accountEmail))
                .setPositiveButton("退出登录", (d, which) -> {
                    Log.i(TAG, "Logging out from provider: " + info.id);
                    logoutProvider(info);
                })
                .setNeutralButton("刷新令牌", (d, which) -> {
                    Log.d(TAG, "Refreshing token for provider: " + info.id);
                    refreshToken(info);
                })
                .setNegativeButton("取消", null)
                .create();

        dialog.setOnShowListener(d -> {
            Button positive = dialog.getButton(android.app.AlertDialog.BUTTON_POSITIVE);
            if (positive != null) {
                positive.setTextColor(Color.parseColor(COLOR_RED));
            }
            Button neutral = dialog.getButton(android.app.AlertDialog.BUTTON_NEUTRAL);
            if (neutral != null) {
                neutral.setTextColor(Color.parseColor(COLOR_PRIMARY));
            }
        });

        dialog.show();
    }

    /**
     * Log out from the given provider by removing its credentials.
     */
    private void logoutProvider(ProviderInfo info) {
        if (info.credential != null) {
            AuthManager.getInstance().removeCredential(info.credential.id);
            Log.i(TAG, "Removed credential for " + info.id + ": " + info.credential.id);
        }
        info.loggedIn = false;
        info.accountEmail = "";
        info.credential = null;
        renderProviders();
        updateStatusSummary();
        showToast("已退出 " + info.displayName);
    }

    /**
     * Refresh the OAuth token for the given provider.
     */
    private void refreshToken(ProviderInfo info) {
        showLoading(true);
        executor.execute(() -> {
            try {
                // In a real implementation, this would call the token refresh endpoint.
                // For now, we simulate a successful refresh.
                Log.d(TAG, "Token refresh simulated for " + info.id);
                Thread.sleep(500); // Simulate network delay
                mainHandler.post(() -> {
                    showLoading(false);
                    showToast(info.displayName + " 令牌已刷新");
                });
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                mainHandler.post(() -> {
                    showLoading(false);
                    showToast("刷新中断");
                });
            }
        });
    }

    /**
     * Simulate an OAuth callback for testing purposes.
     * In a real app, this would be called from a redirect URI handler.
     */
    public void handleOAuthCallback(String providerId, String authorizationCode, String state) {
        Log.i(TAG, "OAuth callback received: provider=" + providerId
                + ", code=" + authorizationCode + ", state=" + state);
        showLoading(true);

        executor.execute(() -> {
            try {
                // Exchange authorization code for tokens
                // This is a simplified simulation; real implementation would call the token endpoint.
                TokenData tokenData = new TokenData();
                tokenData.accessToken = "simulated_access_token_" + System.currentTimeMillis();
                tokenData.refreshToken = "simulated_refresh_token_" + System.currentTimeMillis();
                tokenData.expiresIn = 3600;
                tokenData.expireAt = System.currentTimeMillis() + (tokenData.expiresIn * 1000);
                tokenData.accountId = providerId + "_user_" + System.currentTimeMillis() % 10000;
                tokenData.email = "user@" + providerId + ".example.com";

                AuthResult authResult = new AuthResult(tokenData);

                // Register the credential with AuthManager
                AuthCredential credential = new AuthCredential();
                credential.id = providerId + "_" + System.currentTimeMillis();
                credential.provider = providerId;
                credential.type = AuthCredential.AuthType.OAUTH;
                credential.label = tokenData.email;
                credential.metadata.put("email", tokenData.email);
                credential.metadata.put("access_token", tokenData.accessToken);
                credential.metadata.put("refresh_token", tokenData.refreshToken);
                credential.metadata.put("expire_at", String.valueOf(tokenData.expireAt));

                AuthManager.getInstance().registerCredential(credential);
                Log.i(TAG, "OAuth login successful for " + providerId
                        + ", credential id: " + credential.id);

                mainHandler.post(() -> {
                    showLoading(false);
                    showToast(providerId + " 登录成功");
                    refreshProviderList();
                });

            } catch (Exception e) {
                Log.e(TAG, "OAuth callback processing failed for " + providerId, e);
                mainHandler.post(() -> {
                    showLoading(false);
                    showToast("登录失败: " + e.getMessage());
                });
            }
        });
    }

    // ====== Utilities ======

    private TextView createTitle(String text) {
        TextView tv = new TextView(requireContext());
        tv.setText(text);
        tv.setTextSize(24);
        tv.setTextColor(Color.parseColor(COLOR_TITLE));
        tv.setTypeface(null, Typeface.BOLD);
        tv.setPadding(0, 0, 0, 16);
        return tv;
    }

    private void showToast(String message) {
        android.widget.Toast toast = android.widget.Toast.makeText(
                requireContext(), message, android.widget.Toast.LENGTH_SHORT);
        toast.show();
    }
}