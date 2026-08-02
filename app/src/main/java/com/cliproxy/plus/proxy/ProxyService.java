package com.cliproxy.plus.proxy;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;

import com.cliproxy.plus.R;
import com.cliproxy.plus.ui.MainActivity;

/**
 * ProxyService - 前台服务，保持代理服务器在后台运行
 * 对应原版 server 的后台常驻模式
 */
public class ProxyService extends Service {

    private static final String TAG = "ProxyService";
    private static final String CHANNEL_ID = "cliproxy_server";
    private static final int NOTIFICATION_ID = 8317;

    private ProxyServer proxyServer;
    private boolean isRunning = false;

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent != null ? intent.getAction() : null;

        if ("START".equals(action)) {
            startProxy();
        } else if ("STOP".equals(action)) {
            stopProxy();
        } else if ("RESTART".equals(action)) {
            stopProxy();
            startProxy();
        }

        return START_STICKY;
    }

    private void startProxy() {
        if (isRunning) return;

        Intent notificationIntent = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(
                this, 0, notificationIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

        Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("CLIProxy Plus")
                .setContentText("代理服务器运行中...")
                .setSmallIcon(android.R.drawable.ic_menu_share)
                .setContentIntent(pendingIntent)
                .setOngoing(true)
                .build();

        startForeground(NOTIFICATION_ID, notification);

        proxyServer = new ProxyServer();
        if (proxyServer.startServer()) {
            isRunning = true;
            updateNotification("代理服务器运行中 (端口: " + proxyServer.getPort() + ")");
        }
    }

    private void stopProxy() {
        if (proxyServer != null) {
            proxyServer.stopServer();
        }
        isRunning = false;
        stopForeground(true);
        stopSelf();
    }

    private void updateNotification(String text) {
        Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("CLIProxy Plus")
                .setContentText(text)
                .setSmallIcon(android.R.drawable.ic_menu_share)
                .setOngoing(true)
                .build();
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) {
            manager.notify(NOTIFICATION_ID, notification);
        }
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "CLIProxy Server",
                    NotificationManager.IMPORTANCE_LOW
            );
            channel.setDescription("CLIProxy Plus 代理服务器通知");
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onDestroy() {
        stopProxy();
        super.onDestroy();
    }

    public boolean isRunning() {
        return isRunning;
    }

    public ProxyServer getProxyServer() {
        return proxyServer;
    }
}