package com.theshuai.specusclient.cli;

import com.theshuai.specusclient.SpecusClientApplication;
import com.theshuai.specusclient.auth.FirstLoginRetry;
import com.theshuai.specusclient.auth.HttpLoginFailure;
import com.theshuai.specusclient.bean.ClientStartupConfig;
import com.theshuai.specusclient.client.NettyClientLifecycle;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/** Owns only the runtime started by this UI. No Spring application/updater is started. */
final class UiRuntime {
    private Thread worker;
    private volatile CliState state;
    private volatile String detail="尚未连接；保存配置不会自动连接", revision="";
    synchronized Map<String,Object> snapshot() {
        boolean running=worker!=null&&worker.isAlive();
        CliState current=state;
        var data=current!=null ? current.snapshot() : new LinkedHashMap<String,Object>(Map.of("phase",running?"http-login":"stopped",
                "controlAuthenticated",false,"businessReady",false,"peers",List.of(),"services",List.of()));
        String phase=(String)data.get("phase");
        data.put("detail",running ? switch(phase) {
            case "ready" -> "转发通道就绪；目录不代表目标服务已通过连通性探测";
            case "control-authenticated" -> "控制通道已认证，等待转发通道就绪";
            case "connecting" -> "正在建立控制通道";
            default -> "正在进行 HTTP 登录";
        } : detail);
        data.put("processRunning",running);data.put("runningRevision",revision);data.put("pid",ProcessHandle.current().pid());return data;
    }
    synchronized void start(ClientStartupConfig config,Path path,String revision,int timeout) throws Exception {
        if(worker!=null&&worker.isAlive()) throw new LocalUi.Failure(409,"本页已有连接正在运行");
        state=new CliState(path);this.revision=revision;
        worker=new Thread(() -> {
            NettyClientLifecycle lifecycle=null;
            try {
                var bean=FirstLoginRetry.login(Duration.ofSeconds(timeout),remaining -> SpecusClientApplication.loginAndBuildSpecus(config,remaining), ignored -> { });
                if(Thread.currentThread().isInterrupted()) return;
                var exit=new ClientExitStatus();
                lifecycle=new NettyClientLifecycle(bean,config,exit,state);
                lifecycle.run(null);
                // Interrupted wait permits cancelling a runtime without a Spring context.
                exit.awaitInterruptibly(); detail="连接已结束，请检查权限和服务端状态后重试";
            } catch(InterruptedException ignored) { Thread.currentThread().interrupt(); }
            catch(Exception error) { detail=error instanceof HttpLoginFailure ? error.getMessage() : "连接失败，请检查配置、网络及服务端状态"; }
            finally {
                // Netty shutdown must run off its event loops, with interruption cleared.
                Thread.interrupted();
                try {if(lifecycle!=null) lifecycle.stop();}
                finally {try {state.close();}finally {state=null;}}
            }
        },"local-ui-runtime");
        worker.start();
    }
    void stop() throws InterruptedException {
        Thread current;
        synchronized(this) { current=worker; if(current==null) return; current.interrupt(); }
        current.join(8000);
        if(current.isAlive()) throw new LocalUi.Failure(409,"连接仍在退出，请稍后再试");
        detail="连接已断开；页面仍可管理配置";
    }
}
