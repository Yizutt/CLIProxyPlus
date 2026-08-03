package com.cliproxy.plus.ui.config;

import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.StateListDrawable;
import android.os.Bundle;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.cardview.widget.CardView;
import androidx.fragment.app.Fragment;

import com.cliproxy.plus.config.ConfigManager;
import com.cliproxy.plus.management.ManagementAPIClient;
import android.os.Handler;
import android.os.Looper;

import org.json.JSONObject;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * ConfigFragment - 配置管理 (纯 Java UI)
 * Material Design 3 暗色主题 · 现代卡片布局
 * 显示 JSON 配置，支持编辑、保存、重载
 */
public class ConfigFragment extends Fragment {

    private static final String TAG = "ConfigFragment";

    // ── Material Design 3 暗色主题色板 ──────────────────────────
    private static final String COLOR_BG          = "#121212";
    private static final String COLOR_SURFACE     = "#2A2A3E";
    private static final String COLOR_PRIMARY     = "#7C3AED";
    private static final String COLOR_SECONDARY   = "#9D4EDD";
    private static final String COLOR_TEXT_PRIMARY = "#E2E8F0";
    private static final String COLOR_TEXT_SECONDARY = "#94A3B8";
    private static final String COLOR_SUCCESS     = "#22C55E";
    private static final String COLOR_WARNING     = "#F59E0B";
    private static final String COLOR_ERROR       = "#EF4444";

    private TextView configContentText;
    private TextView statusText;
    private TextView lastSavedText;
    private LinearLayout root;
    private String currentConfigYaml = "";
    private String currentConfigJson = "";

    @Nullable
    @Override
    public View onCreateView(@NonNull android.view.LayoutInflater inflater,
                              @Nullable ViewGroup container,
                              @Nullable Bundle savedInstanceState) {
        ScrollView scrollView = new ScrollView(requireContext());
        scrollView.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
        scrollView.setPadding(20, 20, 20, 20);
        scrollView.setBackgroundColor(Color.parseColor(COLOR_BG));
        scrollView.setVerticalScrollBarEnabled(true);

        root = new LinearLayout(requireContext());
        root.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        root.setOrientation(LinearLayout.VERTICAL);

        // 标题区域
        root.addView(createHeaderSection());

        // 状态卡片
        statusText = new TextView(requireContext());
        lastSavedText = new TextView(requireContext());
        root.addView(createStatusCard());

        // 操作按钮栏
        root.addView(createActionBar());

        // 配置内容卡片（JSON 代码卡片）
        configContentText = new TextView(requireContext());
        configContentText.setTextSize(12);
        configContentText.setTextColor(Color.parseColor(COLOR_TEXT_PRIMARY));
        configContentText.setTypeface(android.graphics.Typeface.MONOSPACE);
        configContentText.setPadding(16, 16, 16, 16);
        configContentText.setLineSpacing(4f, 1f);
        configContentText.setGravity(Gravity.TOP | Gravity.START);

        root.addView(createConfigContentCard());

        // 底部间距
        View spacer = new View(requireContext());
        spacer.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 40));
        root.addView(spacer);

        scrollView.addView(root);
        return scrollView;
    }

    @Override
    public void onResume() {
        super.onResume();
        refreshConfig();
    }

    // ═══════════════════════════════════════════════════════════════
    //  标题区域
    // ═══════════════════════════════════════════════════════════════

    private LinearLayout createHeaderSection() {
        LinearLayout header = new LinearLayout(requireContext());
        header.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        header.setOrientation(LinearLayout.VERTICAL);
        header.setPadding(0, 8, 0, 20);

        // 主标题
        TextView title = new TextView(requireContext());
        title.setText("配置管理");
        title.setTextSize(26);
        title.setTextColor(Color.parseColor(COLOR_TEXT_PRIMARY));
        title.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        title.setPadding(0, 0, 0, 4);

        // 副标题
        TextView subtitle = new TextView(requireContext());
        subtitle.setText("CLIProxy Plus 运行配置");
        subtitle.setTextSize(13);
        subtitle.setTextColor(Color.parseColor(COLOR_TEXT_SECONDARY));

        // 标题下方装饰线
        View divider = new View(requireContext());
        LinearLayout.LayoutParams divParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 2);
        divParams.setMargins(0, 12, 0, 0);
        divider.setLayoutParams(divParams);
        divider.setBackgroundColor(Color.parseColor(COLOR_PRIMARY));

        header.addView(title);
        header.addView(subtitle);
        header.addView(divider);
        return header;
    }

    // ═══════════════════════════════════════════════════════════════
    //  操作按钮栏
    // ═══════════════════════════════════════════════════════════════

    private LinearLayout createActionBar() {
        LinearLayout bar = new LinearLayout(requireContext());
        bar.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setPadding(0, 0, 0, 16);

        // 编辑按钮
        Button editButton = createStyledButton("✎ 编辑配置", COLOR_PRIMARY, true);
        LinearLayout.LayoutParams editParams = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f);
        editParams.setMargins(0, 0, 6, 0);
        editButton.setLayoutParams(editParams);
        editButton.setOnClickListener(v -> showEditDialog());

        // 保存按钮
        Button saveButton = createStyledButton("💾 保存", COLOR_SUCCESS, true);
        LinearLayout.LayoutParams saveParams = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f);
        saveParams.setMargins(6, 0, 6, 0);
        saveButton.setLayoutParams(saveParams);
        saveButton.setOnClickListener(v -> saveConfig());

        // 重载按钮
        Button reloadButton = createStyledButton("⟳ 重载", COLOR_SURFACE, false);
        LinearLayout.LayoutParams reloadParams = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f);
        reloadParams.setMargins(6, 0, 0, 0);
        reloadButton.setLayoutParams(reloadParams);
        reloadButton.setOnClickListener(v -> reloadConfig());

        bar.addView(editButton);
        bar.addView(saveButton);
        bar.addView(reloadButton);

        return bar;
    }

    /**
     * 创建统一风格的按钮
     * @param filled 实心(true) 或 描边(false)
     */
    private Button createStyledButton(String text, String bgColor, boolean filled) {
        Button btn = new Button(requireContext());
        btn.setText(text);
        btn.setTextColor(Color.parseColor(filled ? "#FFFFFF" : COLOR_TEXT_PRIMARY));
        btn.setPadding(16, 12, 16, 12);
        btn.setAllCaps(false);
        btn.setTextSize(13);
        btn.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        btn.setMinHeight(0);
        btn.setMinWidth(0);

        // 圆角背景
        GradientDrawable drawable = new GradientDrawable();
        drawable.setShape(GradientDrawable.RECTANGLE);
        drawable.setCornerRadius(12);

        if (filled) {
            drawable.setColor(Color.parseColor(bgColor));
        } else {
            drawable.setColor(Color.parseColor(bgColor));
            drawable.setStroke(2, Color.parseColor("#3A3A4E"));
        }

        // 按压态
        StateListDrawable states = new StateListDrawable();
        float[] hsv = new float[3];
        Color.colorToHSV(Color.parseColor(bgColor), hsv);
        hsv[2] = Math.max(0, hsv[2] - 0.15f);
        int pressedColor = Color.HSVToColor(hsv);

        GradientDrawable pressedDrawable = new GradientDrawable();
        pressedDrawable.setShape(GradientDrawable.RECTANGLE);
        pressedDrawable.setCornerRadius(12);
        pressedDrawable.setColor(pressedColor);
        if (!filled) {
            pressedDrawable.setStroke(2, Color.parseColor(COLOR_PRIMARY));
        }

        states.addState(new int[]{android.R.attr.state_pressed}, pressedDrawable);
        states.addState(new int[]{}, drawable);

        btn.setBackground(states);
        return btn;
    }

    // ═══════════════════════════════════════════════════════════════
    //  状态卡片
    // ═══════════════════════════════════════════════════════════════

    private CardView createStatusCard() {
        CardView card = new CardView(requireContext());
        LinearLayout.LayoutParams cardParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        cardParams.setMargins(0, 0, 0, 16);
        card.setLayoutParams(cardParams);
        card.setCardBackgroundColor(Color.parseColor(COLOR_SURFACE));
        card.setRadius(16);
        card.setCardElevation(0);
        card.setUseCompatPadding(true);
        card.setPreventCornerOverlap(true);

        LinearLayout content = new LinearLayout(requireContext());
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(20, 18, 20, 18);

        // 顶栏：标题 + 状态指示
        LinearLayout topRow = new LinearLayout(requireContext());
        topRow.setOrientation(LinearLayout.HORIZONTAL);
        topRow.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));

        // 状态指示圆点
        View statusDot = new View(requireContext());
        LinearLayout.LayoutParams dotParams = new LinearLayout.LayoutParams(10, 10);
        dotParams.setMargins(0, 6, 10, 0);
        dotParams.gravity = Gravity.CENTER_VERTICAL;
        statusDot.setLayoutParams(dotParams);

        GradientDrawable dotBg = new GradientDrawable();
        dotBg.setShape(GradientDrawable.OVAL);
        dotBg.setColor(Color.parseColor(COLOR_SUCCESS));
        statusDot.setBackground(dotBg);

        // 标题
        TextView titleView = new TextView(requireContext());
        titleView.setText("配置状态");
        titleView.setTextSize(16);
        titleView.setTextColor(Color.parseColor(COLOR_TEXT_PRIMARY));
        titleView.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);

        topRow.addView(statusDot);
        topRow.addView(titleView);
        content.addView(topRow);

        // 间距
        View spacing1 = new View(requireContext());
        spacing1.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 12));
        content.addView(spacing1);

        // 分隔线
        View divider = new View(requireContext());
        LinearLayout.LayoutParams divParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 1);
        divider.setLayoutParams(divParams);
        divider.setBackgroundColor(Color.parseColor("#3A3A4E"));
        content.addView(divider);

        // 间距
        View spacing2 = new View(requireContext());
        spacing2.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 12));
        content.addView(spacing2);

        // 状态文本
        statusText.setTextSize(14);
        statusText.setTextColor(Color.parseColor(COLOR_SUCCESS));
        statusText.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        statusText.setPadding(0, 0, 0, 6);
        content.addView(statusText);

        // 最后保存时间
        lastSavedText.setTextSize(12);
        lastSavedText.setTextColor(Color.parseColor(COLOR_TEXT_SECONDARY));
        content.addView(lastSavedText);

        card.addView(content);
        return card;
    }

    // ═══════════════════════════════════════════════════════════════
    //  配置内容卡片（代码风格）
    // ═══════════════════════════════════════════════════════════════

    private CardView createConfigContentCard() {
        CardView card = new CardView(requireContext());
        LinearLayout.LayoutParams cardParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        cardParams.setMargins(0, 0, 0, 0);
        card.setLayoutParams(cardParams);
        card.setCardBackgroundColor(Color.parseColor(COLOR_SURFACE));
        card.setRadius(16);
        card.setCardElevation(0);
        card.setUseCompatPadding(true);
        card.setPreventCornerOverlap(true);

        LinearLayout content = new LinearLayout(requireContext());
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(0, 0, 0, 0);

        // ── 卡片头部 ──────────────────────────────────────
        LinearLayout header = new LinearLayout(requireContext());
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setPadding(20, 18, 20, 14);
        header.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));

        // 文件图标标记
        TextView iconLabel = new TextView(requireContext());
        iconLabel.setText("{ }");
        iconLabel.setTextSize(14);
        iconLabel.setTypeface(android.graphics.Typeface.MONOSPACE);
        iconLabel.setTextColor(Color.parseColor(COLOR_PRIMARY));
        iconLabel.setPadding(0, 0, 10, 0);

        TextView titleView = new TextView(requireContext());
        titleView.setText("配置文件");
        titleView.setTextSize(16);
        titleView.setTextColor(Color.parseColor(COLOR_TEXT_PRIMARY));
        titleView.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);

        header.addView(iconLabel);
        header.addView(titleView);
        content.addView(header);

        // 分隔线
        View divider = new View(requireContext());
        LinearLayout.LayoutParams divParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 1);
        divider.setLayoutParams(divParams);
        divider.setBackgroundColor(Color.parseColor("#3A3A4E"));
        content.addView(divider);

        // ── 代码区域 ──────────────────────────────────────
        // 代码行号背景
        LinearLayout codeArea = new LinearLayout(requireContext());
        codeArea.setOrientation(LinearLayout.HORIZONTAL);
        codeArea.setPadding(0, 0, 0, 0);
        codeArea.setBackgroundColor(Color.parseColor("#1A1A2E"));

        // 行号栏
        TextView lineNumbers = new TextView(requireContext());
        lineNumbers.setTextSize(12);
        lineNumbers.setTextColor(Color.parseColor("#4A4A5E"));
        lineNumbers.setTypeface(android.graphics.Typeface.MONOSPACE);
        lineNumbers.setPadding(14, 16, 10, 16);
        lineNumbers.setGravity(Gravity.TOP | Gravity.END);
        lineNumbers.setLineSpacing(4f, 1f);

        // 分隔竖线
        View lineDivider = new View(requireContext());
        lineDivider.setLayoutParams(new LinearLayout.LayoutParams(1, ViewGroup.LayoutParams.MATCH_PARENT));
        lineDivider.setBackgroundColor(Color.parseColor("#3A3A4E"));

        // 代码内容
        configContentText.setPadding(14, 16, 16, 16);

        codeArea.addView(lineNumbers);
        codeArea.addView(lineDivider);
        codeArea.addView(configContentText);

        content.addView(codeArea);

        // ── 底部操作栏 ────────────────────────────────────
        LinearLayout footer = new LinearLayout(requireContext());
        footer.setOrientation(LinearLayout.HORIZONTAL);
        footer.setPadding(16, 12, 16, 12);
        footer.setGravity(Gravity.CENTER_VERTICAL);

        // 行数/大小提示
        TextView infoText = new TextView(requireContext());
        infoText.setTextSize(11);
        infoText.setTextColor(Color.parseColor(COLOR_TEXT_SECONDARY));
        infoText.setText("JSON · 只读，点击编辑修改");

        // 编辑快捷按钮
        Button quickEditBtn = new Button(requireContext());
        quickEditBtn.setText("编辑");
        quickEditBtn.setTextSize(12);
        quickEditBtn.setTextColor(Color.parseColor("#FFFFFF"));
        quickEditBtn.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        quickEditBtn.setAllCaps(false);
        quickEditBtn.setPadding(14, 8, 14, 8);
        quickEditBtn.setMinHeight(0);
        quickEditBtn.setMinWidth(0);

        GradientDrawable quickBtnBg = new GradientDrawable();
        quickBtnBg.setShape(GradientDrawable.RECTANGLE);
        quickBtnBg.setCornerRadius(8);
        quickBtnBg.setColor(Color.parseColor(COLOR_PRIMARY));
        quickEditBtn.setBackground(quickBtnBg);
        quickEditBtn.setOnClickListener(v -> showEditDialog());

        LinearLayout.LayoutParams footerParams = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f);
        infoText.setLayoutParams(footerParams);

        footer.addView(infoText);
        footer.addView(quickEditBtn);
        content.addView(footer);

        card.addView(content);
        return card;
    }

    // ═══════════════════════════════════════════════════════════════
    //  编辑对话框
    // ═══════════════════════════════════════════════════════════════

    private void showEditDialog() {
        android.app.AlertDialog.Builder builder = new android.app.AlertDialog.Builder(requireContext(),
                android.R.style.Theme_Material_Dialog_NoActionBar);

        // 自定义整个对话框布局
        LinearLayout dialogLayout = new LinearLayout(requireContext());
        dialogLayout.setOrientation(LinearLayout.VERTICAL);
        dialogLayout.setPadding(24, 20, 24, 20);
        dialogLayout.setBackgroundColor(Color.parseColor(COLOR_BG));

        // 对话框标题
        TextView dialogTitle = new TextView(requireContext());
        dialogTitle.setText("编辑配置");
        dialogTitle.setTextSize(20);
        dialogTitle.setTextColor(Color.parseColor(COLOR_TEXT_PRIMARY));
        dialogTitle.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        dialogTitle.setPadding(0, 0, 0, 8);
        dialogLayout.addView(dialogTitle);

        // 提示文字
        TextView hintText = new TextView(requireContext());
        hintText.setText("以 JSON 格式编辑配置，修改后点击保存即可生效");
        hintText.setTextSize(13);
        hintText.setTextColor(Color.parseColor(COLOR_TEXT_SECONDARY));
        hintText.setPadding(0, 0, 0, 16);
        dialogLayout.addView(hintText);

        // 编辑框 - 代码编辑器风格
        final EditText editorInput = new EditText(requireContext());
        editorInput.setText(currentConfigJson);
        editorInput.setTextColor(Color.parseColor(COLOR_TEXT_PRIMARY));
        editorInput.setHintTextColor(Color.parseColor("#4A4A5E"));
        editorInput.setPadding(16, 16, 16, 16);
        editorInput.setTextSize(12);
        editorInput.setTypeface(android.graphics.Typeface.MONOSPACE);
        editorInput.setGravity(Gravity.TOP);
        editorInput.setMinLines(18);
        editorInput.setMaxLines(28);
        editorInput.setHorizontalScrollBarEnabled(true);
        editorInput.setVerticalScrollBarEnabled(true);

        // 编辑框背景 - 代码风格
        GradientDrawable editorBg = new GradientDrawable();
        editorBg.setShape(GradientDrawable.RECTANGLE);
        editorBg.setCornerRadius(12);
        editorBg.setColor(Color.parseColor("#1A1A2E"));
        editorBg.setStroke(1, Color.parseColor("#3A3A4E"));
        editorInput.setBackground(editorBg);

        LinearLayout.LayoutParams editorParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        editorInput.setLayoutParams(editorParams);

        dialogLayout.addView(editorInput);

        // 按钮行
        LinearLayout buttonRow = new LinearLayout(requireContext());
        buttonRow.setOrientation(LinearLayout.HORIZONTAL);
        buttonRow.setPadding(0, 20, 0, 0);

        // 取消按钮（描边）
        Button cancelBtn = new Button(requireContext());
        LinearLayout.LayoutParams cancelParams = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f);
        cancelParams.setMargins(0, 0, 6, 0);
        cancelBtn.setLayoutParams(cancelParams);
        cancelBtn.setText("取消");
        cancelBtn.setTextColor(Color.parseColor(COLOR_TEXT_PRIMARY));
        cancelBtn.setTextSize(14);
        cancelBtn.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        cancelBtn.setAllCaps(false);
        cancelBtn.setPadding(12, 12, 12, 12);
        cancelBtn.setMinHeight(0);
        cancelBtn.setMinWidth(0);

        GradientDrawable cancelBg = new GradientDrawable();
        cancelBg.setShape(GradientDrawable.RECTANGLE);
        cancelBg.setCornerRadius(12);
        cancelBg.setColor(Color.parseColor(COLOR_SURFACE));
        cancelBg.setStroke(2, Color.parseColor("#3A3A4E"));
        cancelBtn.setBackground(cancelBg);
        cancelBtn.setOnClickListener(v -> {
            // dismiss via the dialog reference
            if (cancelBtn.getParent() != null) {
                cancelBtn.post(() -> {
                    // Find dialog and dismiss
                    View parent = cancelBtn;
                    while (parent.getParent() instanceof View) {
                        parent = (View) parent.getParent();
                    }
                    if (parent.getParent() instanceof android.app.Dialog) {
                        ((android.app.Dialog) parent.getParent()).dismiss();
                    }
                });
            }
        });

        // 保存按钮（实心）
        Button saveBtn = new Button(requireContext());
        LinearLayout.LayoutParams saveParams = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f);
        saveParams.setMargins(6, 0, 0, 0);
        saveBtn.setLayoutParams(saveParams);
        saveBtn.setText("保存配置");
        saveBtn.setTextColor(Color.parseColor("#FFFFFF"));
        saveBtn.setTextSize(14);
        saveBtn.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        saveBtn.setAllCaps(false);
        saveBtn.setPadding(12, 12, 12, 12);
        saveBtn.setMinHeight(0);
        saveBtn.setMinWidth(0);

        GradientDrawable saveBg = new GradientDrawable();
        saveBg.setShape(GradientDrawable.RECTANGLE);
        saveBg.setCornerRadius(12);
        saveBg.setColor(Color.parseColor(COLOR_PRIMARY));
        saveBtn.setBackground(saveBg);
        saveBtn.setOnClickListener(v -> {
            String editedJson = editorInput.getText().toString().trim();
            if (editedJson.isEmpty()) {
                Toast.makeText(requireContext(), "配置内容不能为空", Toast.LENGTH_SHORT).show();
                return;
            }
            applyEditedConfig(editedJson);
            // Dismiss dialog
            View parent = saveBtn;
            while (parent.getParent() instanceof View) {
                parent = (View) parent.getParent();
            }
            if (parent.getParent() instanceof android.app.Dialog) {
                ((android.app.Dialog) parent.getParent()).dismiss();
            }
        });

        buttonRow.addView(cancelBtn);
        buttonRow.addView(saveBtn);
        dialogLayout.addView(buttonRow);

        builder.setView(dialogLayout);
        builder.show();
    }

    // ═══════════════════════════════════════════════════════════════
    //  配置操作
    // ═══════════════════════════════════════════════════════════════

    private void refreshConfig() {
        try {
            ConfigManager config = getConfigManager();
            if (config == null) {
                setStatusText("未初始化", COLOR_ERROR);
                setText(lastSavedText, "ConfigManager 尚未初始化", COLOR_TEXT_SECONDARY);
                return;
            }

            // 读取当前配置
            currentConfigJson = config.getConfigJson();
            currentConfigYaml = config.exportYaml();

            // 格式化为更易读的 JSON
            try {
                JSONObject jsonObj = new JSONObject(currentConfigJson);
                currentConfigJson = jsonObj.toString(2);
            } catch (Exception ignored) {
                // 保持原样
            }

            // 显示配置内容（优先显示 YAML 风格，没有则显示 JSON）
            String displayText;
            if (currentConfigYaml != null && !currentConfigYaml.isEmpty() && !currentConfigYaml.startsWith("# CLIProxy")) {
                displayText = currentConfigYaml;
            } else {
                displayText = currentConfigJson;
            }
            configContentText.setText(displayText);

            // 解析关键状态
            int port = config.getInt("port", 8317);
            boolean debug = config.getBoolean("debug", false);
            String host = config.getString("host", "");

            StringBuilder status = new StringBuilder();
            status.append("配置已加载");
            if (debug) status.append("  ·  调试模式");
            if (!host.isEmpty()) status.append("  ·  主机: ").append(host);
            status.append("  ·  端口: ").append(port);

            setStatusText(status.toString(), COLOR_SUCCESS);

            String timeStr = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
                    .format(new Date());
            setText(lastSavedText, "最后刷新: " + timeStr, COLOR_TEXT_SECONDARY);

            // 更新行号
            updateLineNumbers(displayText);

            Log.d(TAG, "Config refreshed: " + currentConfigJson);

        } catch (Exception e) {
            Log.e(TAG, "Error refreshing config", e);
            setStatusText("配置加载失败: " + e.getMessage(), COLOR_ERROR);
        }
    }

    /**
     * 更新代码行号显示
     */
    private void updateLineNumbers(String text) {
        // Find the lineNumbers TextView inside the config card
        // We rebuild it from the root
        if (configContentText == null) return;

        // Walk up to find the code area container
        View parent = (View) configContentText.getParent();
        if (parent instanceof LinearLayout) {
            LinearLayout codeArea = (LinearLayout) parent;
            TextView lineNumbers = (TextView) codeArea.getChildAt(0);
            if (lineNumbers != null) {
                int lines = text.split("\n").length;
                StringBuilder sb = new StringBuilder();
                for (int i = 1; i <= lines; i++) {
                    sb.append(i).append("\n");
                }
                lineNumbers.setText(sb.toString().trim());
            }
        }
    }

    private void saveConfig() {
        try {
            ConfigManager config = getConfigManager();
            if (config == null) {
                Toast.makeText(requireContext(), "ConfigManager 未初始化", Toast.LENGTH_SHORT).show();
                return;
            }

            config.saveConfig();
            setText(lastSavedText, "最后保存: " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss",
                    Locale.getDefault()).format(new Date()), COLOR_TEXT_SECONDARY);
            Toast.makeText(requireContext(), "配置已保存", Toast.LENGTH_SHORT).show();
            Log.i(TAG, "Config saved");

        } catch (Exception e) {
            Log.e(TAG, "Error saving config", e);
            Toast.makeText(requireContext(), "保存失败: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void reloadConfig() {
        try {
            ConfigManager config = getConfigManager();
            if (config == null) {
                Toast.makeText(requireContext(), "ConfigManager 未初始化", Toast.LENGTH_SHORT).show();
                return;
            }

            config.reload();
            refreshConfig();
            Toast.makeText(requireContext(), "配置已重载", Toast.LENGTH_SHORT).show();
            Log.i(TAG, "Config reloaded");

        } catch (Exception e) {
            Log.e(TAG, "Error reloading config", e);
            Toast.makeText(requireContext(), "重载失败: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void applyEditedConfig(String editedJson) {
        try {
            // 验证 JSON 合法性
            new JSONObject(editedJson);

            ConfigManager config = getConfigManager();
            if (config == null) {
                Toast.makeText(requireContext(), "ConfigManager 未初始化", Toast.LENGTH_SHORT).show();
                return;
            }

            config.applyConfig(editedJson);
            refreshConfig();
            Toast.makeText(requireContext(), "配置已应用", Toast.LENGTH_SHORT).show();
            Log.i(TAG, "Config applied from editor");

        } catch (org.json.JSONException e) {
            Log.e(TAG, "Invalid JSON in editor", e);
            Toast.makeText(requireContext(), "JSON 格式错误: " + e.getMessage(), Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            Log.e(TAG, "Error applying config from editor", e);
            Toast.makeText(requireContext(), "应用失败: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  工具方法
    // ═══════════════════════════════════════════════════════════════

    private ConfigManager getConfigManager() {
        try {
            return ConfigManager.getInstance();
        } catch (IllegalStateException e) {
            Log.w(TAG, "ConfigManager not initialized", e);
            return null;
        }
    }

    private void setStatusText(String text, String color) {
        if (statusText != null) {
            statusText.setText(text);
            statusText.setTextColor(Color.parseColor(color));
            statusText.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        }
    }

    private void setText(TextView tv, String text, String color) {
        if (tv != null) {
            tv.setText(text);
            tv.setTextColor(Color.parseColor(color));
        }
    }
}