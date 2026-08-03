package com.cliproxy.plus.ui.logs;

import android.graphics.Color;
import android.graphics.Typeface;
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
 * - Scrollable log list with color-coded levels (debug=gray, info=blue, warn=yellow, error=red)
 * - Auto-scroll toggle to follow new logs
 * - Clear button to wipe the log buffer
 * - Filter input for searching/filtering logs by text
 * - Reads logcat output filtered by the app's package name
 * - Allows in-app components to push logs via LogBuffer.push()
 */
public class LogsFragment extends Fragment {

    // ── Theme colors matching project dark theme ──
    private static final String COLOR_BG = "#1E1E2E";
    private static final String COLOR_PRIMARY = "#7C3AED";
    private static final String COLOR_TEXT = "#CDD6F4";
    private static final String COLOR_TEXT_SECONDARY = "#A6ADC8";
    private static final String COLOR_SURFACE = "#313244";
    private static final String COLOR_BORDER = "#45475A";

    // ── Log level colors ──
    private static final String COLOR_DEBUG = "#A6ADC8";
    private static final String COLOR_INFO = "#3B82F6";
    private static final String COLOR_WARN = "#F59E0B";
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
        rootLayout.setPadding(12, 12, 12, 12);

        buildToolbar();
        buildLogArea();
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

    private void buildToolbar() {
        // Top bar: filter + auto-scroll + clear
        LinearLayout toolbar = new LinearLayout(requireContext());
        toolbar.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        toolbar.setOrientation(LinearLayout.HORIZONTAL);
        toolbar.setGravity(Gravity.CENTER_VERTICAL);
        toolbar.setPadding(0, 0, 0, 8);

        // Filter input
        filterInput = new EditText(requireContext());
        LinearLayout.LayoutParams filterParams = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f);
        filterInput.setLayoutParams(filterParams);
        filterInput.setHint("Filter logs...");
        filterInput.setTextColor(Color.parseColor(COLOR_TEXT));
        filterInput.setHintTextColor(Color.parseColor(COLOR_TEXT_SECONDARY));
        filterInput.setBackgroundColor(Color.parseColor(COLOR_SURFACE));
        filterInput.setPadding(12, 8, 12, 8);
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
        autoScrollToggle.setText("Auto");
        autoScrollToggle.setTextColor(Color.parseColor(COLOR_PRIMARY));
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

        // Clear button
        clearButton = new Button(requireContext());
        clearButton.setText("Clear");
        clearButton.setTextColor(Color.parseColor(COLOR_TEXT));
        clearButton.setBackgroundColor(Color.parseColor(COLOR_SURFACE));
        clearButton.setTextSize(13);
        clearButton.setPadding(12, 6, 12, 6);
        clearButton.setTypeface(null, Typeface.BOLD);
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

        toolbar.addView(filterInput);
        toolbar.addView(autoScrollToggle);
        toolbar.addView(clearButton);
        rootLayout.addView(toolbar);
    }

    private void buildLogArea() {
        logScrollView = new ScrollView(requireContext());
        logScrollView.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0, 1.0f));
        logScrollView.setBackgroundColor(Color.parseColor(COLOR_SURFACE));
        logScrollView.setPadding(0, 0, 0, 0);

        // Wrap in HorizontalScrollView so long lines don't get clipped
        HorizontalScrollView hScroll = new HorizontalScrollView(requireContext());
        hScroll.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
        hScroll.setHorizontalScrollBarEnabled(true);

        logContainer = new LinearLayout(requireContext());
        logContainer.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        logContainer.setOrientation(LinearLayout.VERTICAL);
        logContainer.setPadding(8, 8, 8, 8);

        hScroll.addView(logContainer);
        logScrollView.addView(hScroll);
        rootLayout.addView(logScrollView);
    }

    private void buildStatusBar() {
        statusText = new TextView(requireContext());
        statusText.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        statusText.setTextColor(Color.parseColor(COLOR_TEXT_SECONDARY));
        statusText.setTextSize(12);
        statusText.setPadding(4, 6, 4, 2);
        statusText.setGravity(Gravity.CENTER_HORIZONTAL);
        rootLayout.addView(statusText);
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
        line.setPadding(0, 1, 0, 1);
        line.setTextSize(11);
        line.setTypeface(Typeface.MONOSPACE);
        line.setSingleLine(false);

        // Format: [HH:mm:ss] LEVEL/TAG: message
        String time = new SimpleDateFormat("HH:mm:ss", Locale.US)
                .format(new Date(entry.timestamp));
        line.setText(String.format(Locale.US, "[%s] %s/%s: %s",
                time, entry.level, entry.tag, entry.message));

        // Color by level
        switch (entry.level) {
            case "DEBUG":
                line.setTextColor(Color.parseColor(COLOR_DEBUG));
                break;
            case "INFO":
                line.setTextColor(Color.parseColor(COLOR_INFO));
                break;
            case "WARN":
                line.setTextColor(Color.parseColor(COLOR_WARN));
                break;
            case "ERROR":
                line.setTextColor(Color.parseColor(COLOR_ERROR));
                break;
            default:
                line.setTextColor(Color.parseColor(COLOR_TEXT));
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