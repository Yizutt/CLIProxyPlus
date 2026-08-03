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
 * ProxyService - 管理 Go 服务器进程的生命周期
 * 使用 ServerManager 启动/停止 rootfs 中的 cliproxy-server
 */
public class ProxyService extends Service {

    private static final String TAG = "ProxyService";
    private static final String CHANNEL_ID = "cliproxy_server";
    private static final int NOTIFICATION_ID = 8317;

    private ServerManager serverManager;

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
        serverManager = new ServerManager(this);
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
        if (serverManager.isRunning()) {
            updateNotification("服务器运行中 (端口: " + serverManager.getPort() + ")");
            return;
        }

        Intent notificationIntent = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(
                this, 0, notificationIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

        Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("CLIProxy Plus")
                .setContentText("正在启动服务器...")
                .setSmallIcon(android.R.drawable.ic_menu_share)
                .setContentIntent(pendingIntent)
                .setOngoing(true)
                .build();

        startForeground(NOTIFICATION_ID, notification);

        if (serverManager.startServer()) {
            updateNotification("服务器运行中 (端口: " + serverManager.getPort() + ")");
        } else {
            updateNotification("服务器启动失败");
        }
    }

    private void stopProxy() {
        serverManager.stopServer();
        updateNotification("服务器已停止");
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
                    CHANNEL_ID, "CLIProxy Server",
                    NotificationManager.IMPORTANCE_LOW);
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
        serverManager.stopServer();
        super.onDestroy();
    }

    public ServerManager getServerManager() {
        return serverManager;
    }
}