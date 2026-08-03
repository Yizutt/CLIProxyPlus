package com.cliproxy.plus.ui.logs;

import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * LogsFragment - Real-time log viewer with color-coded levels, filtering, auto-scroll, and clear.
 * <p>
 * Features:
 * - Scrollable log list with color-coded levels (debug=gray, info=success, warn=amber, error=red)
 * - Auto-scroll toggle to follow new logs
 * - Clear button to wipe the log buffer
 * - Filter input for searching/filtering logs by text
 * - Card-based Material Design 3 dark theme layout
 * - Reads logcat output filtered by the app's package name
 * - Allows in-app components to push logs via LogBuffer.push()
 */
public class LogsFragment extends Fragment {

    // ── Material Design 3 Dark Theme Colors ──
    private static final String COLOR_BG = "#121212";
    private static final String COLOR_SURFACE = "#2A2A3E";
    private static final String COLOR_PRIMARY = "#7C3AED";
    private static final String COLOR_SECONDARY = "#9D4EDD";
    private static final String COLOR_TEXT_PRIMARY = "#E2E8F0";
    private static final String COLOR_TEXT_SECONDARY = "#94A3B8";
    private static final String COLOR_SUCCESS = "#22C55E";
    private static final String COLOR_WARNING = "#F59E0B";
    private static final String COLOR_ERROR = "#EF4444";

    // ── UI Components ──
    private LinearLayout rootLayout;
    private ScrollView logScrollView;
    private LinearLayout logContainer;
    private EditText filterInput;
    private CheckBox autoScrollToggle;
    private Button clearButton;
    private TextView statusText;

    // ── State ──
    private final List<LogEntry> allLogs = new ArrayList<>();
    private final List<LogEntry> filteredLogs = new ArrayList<>();
    private String currentFilter = "";
    private boolean autoScroll = true;
    private final Handler refreshHandler = new Handler(Looper.getMainLooper());
    private final AtomicBoolean readingLogcat = new AtomicBoolean(false);
    private Thread logcatThread;

    // ── Log entry model ──
    private static class LogEntry {
        final long timestamp;
        final String level;
        final String tag;
        final String message;

        LogEntry(long timestamp, String level, String tag, String message) {
            this.timestamp = timestamp;
            this.level = level;
            this.tag = tag;
            this.message = message;
        }

        boolean matchesFilter(String filter) {
            if (filter == null || filter.isEmpty()) return true;
            String lower = filter.toLowerCase(Locale.US);
            return tag.toLowerCase(Locale.US).contains(lower)
                    || message.toLowerCase(Locale.US).contains(lower)
                    || level.toLowerCase(Locale.US).contains(lower);
        }
    }

    // ── Public log buffer for in-app components ──
    private static final List<LogEntry> sharedBuffer = new ArrayList<>();
    private static final Object bufferLock = new Object();

    /**
     * Push a log entry from any in-app component.
     */
    public static void push(String level, String tag, String message) {
        synchronized (bufferLock) {
            sharedBuffer.add(new LogEntry(System.currentTimeMillis(), level, tag, message));
            if (sharedBuffer.size() > 2000) {
                sharedBuffer.remove(0);
            }
        }
    }

    public static void d(String tag, String message) { push("DEBUG", tag, message); }
    public static void i(String tag, String message) { push("INFO", tag, message); }
    public static void w(String tag, String message) { push("WARN", tag, message); }
    public static void e(String tag, String message) { push("ERROR", tag, message); }

    // ── Drawable Helpers ──

    /**
     * Create a rounded rectangle drawable for card backgrounds.
     */
    private GradientDrawable makeRoundedBg(int color, float radiusPx) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setShape(GradientDrawable.RECTANGLE);
        drawable.setCornerRadius(radiusPx);
        drawable.setColor(color);
        return drawable;
    }

    /**
     * Create a rounded rectangle drawable with a stroke border.
     */
    private GradientDrawable makeRoundedBgWithBorder(int fillColor, int strokeColor, float strokeWidthPx, float radiusPx) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setShape(GradientDrawable.RECTANGLE);
        drawable.setCornerRadius(radiusPx);
        drawable.setColor(fillColor);
        drawable.setStroke((int) strokeWidthPx, strokeColor);
        return drawable;
    }

    // ── Lifecycle ──

    @Nullable
    @Override
    public View onCreateView(@NonNull android.view.LayoutInflater inflater,
                             @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        rootLayout = new LinearLayout(requireContext());
        rootLayout.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
        rootLayout.setOrientation(LinearLayout.VERTICAL);
        rootLayout.setBackgroundColor(Color.parseColor(COLOR_BG));
        rootLayout.setPadding(16, 16, 16, 16);

        buildToolbarCard();
        buildLogAreaCard();
        buildStatusBar();

        // Initial status
        updateStatus(0);

        return rootLayout;
    }

    @Override
    public void onResume() {
        super.onResume();
        startLogcatReader();
        refreshHandler.post(refreshRunnable);
    }

    @Override
    public void onPause() {
        super.onPause();
        refreshHandler.removeCallbacks(refreshRunnable);
        stopLogcatReader();
    }

    // ── UI Builders ──

    private void buildToolbarCard() {
        // Outer card container for the toolbar
        LinearLayout toolbarCard = new LinearLayout(requireContext());
        toolbarCard.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        toolbarCard.setOrientation(LinearLayout.VERTICAL);
        toolbarCard.setBackground(makeRoundedBg(Color.parseColor(COLOR_SURFACE), 16f));
        toolbarCard.setPadding(12, 12, 12, 12);
        toolbarCard.setElevation(4f);

        // Title label
        TextView titleLabel = new TextView(requireContext());
        titleLabel.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        titleLabel.setText("Log Viewer");
        titleLabel.setTextColor(Color.parseColor(COLOR_TEXT_PRIMARY));
        titleLabel.setTextSize(15);
        titleLabel.setTypeface(null, Typeface.BOLD);
        titleLabel.setPadding(4, 0, 0, 10);

        // Top row: filter + auto-scroll + clear
        LinearLayout toolbarRow = new LinearLayout(requireContext());
        toolbarRow.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        toolbarRow.setOrientation(LinearLayout.HORIZONTAL);
        toolbarRow.setGravity(Gravity.CENTER_VERTICAL);

        // Filter input with rounded background
        filterInput = new EditText(requireContext());
        LinearLayout.LayoutParams filterParams = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f);
        filterInput.setLayoutParams(filterParams);
        filterInput.setHint("Filter logs...");
        filterInput.setTextColor(Color.parseColor(COLOR_TEXT_PRIMARY));
        filterInput.setHintTextColor(Color.parseColor(COLOR_TEXT_SECONDARY));
        filterInput.setBackground(makeRoundedBgWithBorder(
                Color.parseColor("#1E1E2E"),
                Color.parseColor("#3A3A4E"),
                1.5f, 12f));
        filterInput.setPadding(14, 10, 14, 10);
        filterInput.setTextSize(14);
        filterInput.setSingleLine(true);
        filterInput.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {}
            @Override
            public void afterTextChanged(Editable s) {
                currentFilter = s != null ? s.toString() : "";
                applyFilter();
            }
        });

        // Auto-scroll toggle
        autoScrollToggle = new CheckBox(requireContext());
        LinearLayout.LayoutParams toggleParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        toggleParams.setMarginStart(8);
        autoScrollToggle.setLayoutParams(toggleParams);
        autoScrollToggle.setText("Auto");
        autoScrollToggle.setTextColor(Color.parseColor(COLOR_TEXT_PRIMARY));
        autoScrollToggle.setTextSize(13);
        autoScrollToggle.setChecked(true);
        autoScrollToggle.setPadding(8, 0, 4, 0);
        autoScrollToggle.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                autoScroll = isChecked;
                if (autoScroll) {
                    scrollToBottom();
                }
            }
        });

        // Clear button with rounded background
        clearButton = new Button(requireContext());
        LinearLayout.LayoutParams clearParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        clearParams.setMarginStart(8);
        clearButton.setLayoutParams(clearParams);
        clearButton.setText("Clear");
        clearButton.setTextColor(Color.parseColor(COLOR_TEXT_PRIMARY));
        clearButton.setBackground(makeRoundedBg(Color.parseColor("#EF4444"), 10f));
        clearButton.setTextSize(13);
        clearButton.setPadding(16, 8, 16, 8);
        clearButton.setTypeface(null, Typeface.BOLD);
        clearButton.setElevation(2f);
        clearButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                synchronized (bufferLock) {
                    sharedBuffer.clear();
                }
                allLogs.clear();
                filteredLogs.clear();
                logContainer.removeAllViews();
                updateStatus(0);
            }
        });

        toolbarRow.addView(filterInput);
        toolbarRow.addView(autoScrollToggle);
        toolbarRow.addView(clearButton);

        toolbarCard.addView(titleLabel);
        toolbarCard.addView(toolbarRow);
        rootLayout.addView(toolbarCard);

        // Add spacing between cards
        View spacer = new View(requireContext());
        spacer.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 12));
        rootLayout.addView(spacer);
    }

    private void buildLogAreaCard() {
        // Outer card container for the log area
        LinearLayout logCard = new LinearLayout(requireContext());
        logCard.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0, 1.0f));
        logCard.setOrientation(LinearLayout.VERTICAL);
        logCard.setBackground(makeRoundedBg(Color.parseColor(COLOR_SURFACE), 16f));
        logCard.setPadding(0, 0, 0, 0);
        logCard.setElevation(4f);

        // Log area header
        TextView logHeader = new TextView(requireContext());
        logHeader.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        logHeader.setText("Log Output");
        logHeader.setTextColor(Color.parseColor(COLOR_TEXT_SECONDARY));
        logHeader.setTextSize(12);
        logHeader.setTypeface(null, Typeface.BOLD);
        logHeader.setPadding(14, 12, 14, 6);

        // ScrollView for log content
        logScrollView = new ScrollView(requireContext());
        logScrollView.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0, 1.0f));
        logScrollView.setBackgroundColor(Color.parseColor("#1A1A2A"));
        logScrollView.setPadding(0, 0, 0, 0);

        // Wrap in HorizontalScrollView so long lines don't get clipped
        HorizontalScrollView hScroll = new HorizontalScrollView(requireContext());
        hScroll.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
        hScroll.setHorizontalScrollBarEnabled(true);
        hScroll.setScrollBarStyle(View.SCROLLBARS_INSIDE_OVERLAY);

        logContainer = new LinearLayout(requireContext());
        logContainer.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        logContainer.setOrientation(LinearLayout.VERTICAL);
        logContainer.setPadding(12, 8, 12, 8);

        hScroll.addView(logContainer);
        logScrollView.addView(hScroll);
        logCard.addView(logHeader);
        logCard.addView(logScrollView);

        // Bottom rounded corners for the inner log area
        GradientDrawable innerBg = new GradientDrawable();
        innerBg.setShape(GradientDrawable.RECTANGLE);
        innerBg.setCornerRadii(new float[]{
                0f, 0f, 0f, 0f,
                16f, 16f, 16f, 16f
        });
        innerBg.setColor(Color.parseColor("#1A1A2A"));
        logScrollView.setBackground(innerBg);

        rootLayout.addView(logCard);
    }

    private void buildStatusBar() {
        // Card container for status bar
        LinearLayout statusCard = new LinearLayout(requireContext());
        statusCard.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        statusCard.setOrientation(LinearLayout.HORIZONTAL);
        statusCard.setBackground(makeRoundedBg(Color.parseColor(COLOR_SURFACE), 16f));
        statusCard.setPadding(14, 10, 14, 10);
        statusCard.setElevation(4f);
        statusCard.setGravity(Gravity.CENTER_VERTICAL);

        // Add spacing above status bar
        View spacer = new View(requireContext());
        spacer.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 12));
        rootLayout.addView(spacer);

        // Status indicator dot
        View statusDot = new View(requireContext());
        LinearLayout.LayoutParams dotParams = new LinearLayout.LayoutParams(8, 8);
        dotParams.setMarginEnd(8);
        statusDot.setLayoutParams(dotParams);
        GradientDrawable dotBg = new GradientDrawable();
        dotBg.setShape(GradientDrawable.OVAL);
        dotBg.setColor(Color.parseColor(COLOR_SUCCESS));
        statusDot.setBackground(dotBg);

        // Status text
        statusText = new TextView(requireContext());
        statusText.setLayoutParams(new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f));
        statusText.setTextColor(Color.parseColor(COLOR_TEXT_SECONDARY));
        statusText.setTextSize(12);
        statusText.setTypeface(null, Typeface.NORMAL);

        // Level legend
        LinearLayout legendLayout = new LinearLayout(requireContext());
        legendLayout.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        legendLayout.setOrientation(LinearLayout.HORIZONTAL);
        legendLayout.setGravity(Gravity.CENTER_VERTICAL);

        legendLayout.addView(makeLegendItem("D", Color.parseColor(COLOR_TEXT_SECONDARY)));
        legendLayout.addView(makeLegendItem("I", Color.parseColor(COLOR_SUCCESS)));
        legendLayout.addView(makeLegendItem("W", Color.parseColor(COLOR_WARNING)));
        legendLayout.addView(makeLegendItem("E", Color.parseColor(COLOR_ERROR)));

        statusCard.addView(statusDot);
        statusCard.addView(statusText);
        statusCard.addView(legendLayout);
        rootLayout.addView(statusCard);
    }

    /**
     * Create a small colored level badge for the legend.
     */
    private View makeLegendItem(String label, int color) {
        LinearLayout item = new LinearLayout(requireContext());
        LinearLayout.LayoutParams itemParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        itemParams.setMarginStart(8);
        item.setLayoutParams(itemParams);
        item.setOrientation(LinearLayout.HORIZONTAL);
        item.setGravity(Gravity.CENTER_VERTICAL);

        // Colored dot
        View dot = new View(requireContext());
        LinearLayout.LayoutParams dotParams = new LinearLayout.LayoutParams(6, 6);
        dotParams.setMarginEnd(3);
        dot.setLayoutParams(dotParams);
        GradientDrawable dotBg = new GradientDrawable();
        dotBg.setShape(GradientDrawable.OVAL);
        dotBg.setColor(color);
        dot.setBackground(dotBg);

        // Label
        TextView labelView = new TextView(requireContext());
        labelView.setText(label);
        labelView.setTextColor(color);
        labelView.setTextSize(10);
        labelView.setTypeface(null, Typeface.BOLD);

        item.addView(dot);
        item.addView(labelView);
        return item;
    }

    // ── Log Rendering ──

    private final Runnable refreshRunnable = new Runnable() {
        @Override
        public void run() {
            drainSharedBuffer();
            refreshHandler.postDelayed(this, 500);
        }
    };

    private void drainSharedBuffer() {
        List<LogEntry> fresh;
        synchronized (bufferLock) {
            if (sharedBuffer.isEmpty()) return;
            fresh = new ArrayList<>(sharedBuffer);
            sharedBuffer.clear();
        }

        allLogs.addAll(fresh);
        // Cap total logs to prevent unbounded memory growth
        if (allLogs.size() > 5000) {
            int excess = allLogs.size() - 5000;
            List<LogEntry> removed = new ArrayList<>(allLogs.subList(0, excess));
            allLogs.subList(0, excess).clear();
            // Remove corresponding entries from filteredLogs too
            filteredLogs.removeAll(removed);
        }

        // Append to filtered view if filter matches
        for (LogEntry entry : fresh) {
            if (entry.matchesFilter(currentFilter)) {
                filteredLogs.add(entry);
                appendLogLine(entry);
            }
        }

        updateStatus(allLogs.size());

        if (autoScroll) {
            scrollToBottom();
        }
    }

    private void applyFilter() {
        filteredLogs.clear();
        logContainer.removeAllViews();

        for (LogEntry entry : allLogs) {
            if (entry.matchesFilter(currentFilter)) {
                filteredLogs.add(entry);
                appendLogLine(entry);
            }
        }

        updateStatus(allLogs.size());

        if (autoScroll) {
            scrollToBottom();
        }
    }

    private void appendLogLine(LogEntry entry) {
        TextView line = new TextView(requireContext());
        line.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        line.setPadding(0, 2, 0, 2);
        line.setTextSize(11);
        line.setTypeface(Typeface.MONOSPACE);
        line.setSingleLine(false);
        line.setLineSpacing(2f, 1f);

        // Format: [HH:mm:ss] LEVEL/TAG: message
        String time = new SimpleDateFormat("HH:mm:ss", Locale.US)
                .format(new Date(entry.timestamp));
        line.setText(String.format(Locale.US, "[%s] %s/%s: %s",
                time, entry.level, entry.tag, entry.message));

        // Color by level using the new theme colors
        switch (entry.level) {
            case "DEBUG":
                line.setTextColor(Color.parseColor(COLOR_TEXT_SECONDARY));
                break;
            case "INFO":
                line.setTextColor(Color.parseColor(COLOR_SUCCESS));
                break;
            case "WARN":
                line.setTextColor(Color.parseColor(COLOR_WARNING));
                break;
            case "ERROR":
                line.setTextColor(Color.parseColor(COLOR_ERROR));
                break;
            default:
                line.setTextColor(Color.parseColor(COLOR_TEXT_PRIMARY));
                break;
        }

        logContainer.addView(line);
    }

    private void scrollToBottom() {
        logScrollView.post(new Runnable() {
            @Override
            public void run() {
                logScrollView.fullScroll(View.FOCUS_DOWN);
            }
        });
    }

    private void updateStatus(int totalCount) {
        int shown = filteredLogs.size();
        String filterSuffix = currentFilter.isEmpty() ? "" : " (filtered to " + shown + ")";
        statusText.setText("Log entries: " + totalCount + filterSuffix);
    }

    // ── Logcat Reader ──

    private void startLogcatReader() {
        if (logcatThread != null && logcatThread.isAlive()) return;
        if (!readingLogcat.compareAndSet(false, true)) return;

        logcatThread = new Thread(new Runnable() {
            @Override
            public void run() {
                Process process = null;
                BufferedReader reader = null;
                try {
                    // Read logcat for the app's process
                    String pid = Integer.toString(android.os.Process.myPid());
                    ProcessBuilder builder = new ProcessBuilder(
                            "logcat", "--pid=" + pid, "-v", "brief");
                    builder.redirectErrorStream(true);
                    process = builder.start();
                    reader = new BufferedReader(
                            new InputStreamReader(process.getInputStream()));

                    String line;
                    while (readingLogcat.get() && (line = reader.readLine()) != null) {
                        parseLogcatLine(line);
                    }
                } catch (Exception ignored) {
                    // logcat reading may fail on some devices/permission configs
                } finally {
                    readingLogcat.set(false);
                    if (reader != null) {
                        try { reader.close(); } catch (Exception ignored) {}
                    }
                    if (process != null) {
                        process.destroy();
                    }
                }
            }
        }, "logcat-reader");
        logcatThread.setDaemon(true);
        logcatThread.start();
    }

    private void stopLogcatReader() {
        readingLogcat.set(false);
        if (logcatThread != null) {
            logcatThread.interrupt();
            logcatThread = null;
        }
    }

    /**
     * Parse a logcat brief-format line: {@code <priority>/<tag>(<pid>): <message>}
     */
    private void parseLogcatLine(String raw) {
        if (raw == null || raw.isEmpty()) return;
        try {
            String level;
            if (raw.startsWith("D/")) level = "DEBUG";
            else if (raw.startsWith("I/")) level = "INFO";
            else if (raw.startsWith("W/")) level = "WARN";
            else if (raw.startsWith("E/")) level = "ERROR";
            else return;

            // Strip the leading "D/I/W/E/"
            String rest = raw.substring(2);
            int parenIdx = rest.indexOf('(');
            int colonIdx = rest.indexOf(": ");
            if (parenIdx < 0 || colonIdx < 0 || colonIdx < parenIdx) return;

            String tag = rest.substring(0, parenIdx);
            String message = rest.substring(colonIdx + 2);

            synchronized (bufferLock) {
                sharedBuffer.add(new LogEntry(System.currentTimeMillis(), level, tag, message));
                if (sharedBuffer.size() > 2000) {
                    sharedBuffer.remove(0);
                }
            }
        } catch (Exception ignored) {
            // skip malformed lines
        }
    }
}