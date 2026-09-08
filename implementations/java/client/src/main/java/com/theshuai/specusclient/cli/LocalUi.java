package com.theshuai.specusclient.cli;

import com.fasterxml.jackson.databind.JsonNode;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.buffer.Unpooled;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;

/** Loopback-only, bounded HTTP adapter. The public shell contains no state or credentials. */
public final class LocalUi {
    static final class Failure extends RuntimeException {
        final int status;
        Failure(int status,String message) { super(message);this.status=status; }
    }
    private final ClientCli.Options options;
    private final String version;
    private final UiRuntime runtime=new UiRuntime();
    private final Map<String,Long> sessions=new HashMap<>();
    private String code="", origin="";
    private long codeExpiry;
    private final Object operations=new Object();
    private LocalUi(ClientCli.Options options,String version) {this.options=options;this.version=version;}
    private static String random() {byte[] bytes=new byte[32];new SecureRandom().nextBytes(bytes);return HexFormat.of().formatHex(bytes);}
    private synchronized String rotate() {code=random();codeExpiry=System.currentTimeMillis()+300_000;return code;}
    private void printCode() {System.out.println("一次性连接码（5 分钟有效；按 Enter 生成新码）：\n"+rotate());System.out.flush();}
    private synchronized Object session(JsonNode body) {
        long now=System.currentTimeMillis();
        if(now>=codeExpiry||code.isEmpty()||!code.equals(body.path("code").asText())) throw new Failure(401,"连接码无效或已过期，请在终端按 Enter 获取新码");
        sessions.entrySet().removeIf(e -> e.getValue()<=now);
        if(sessions.size()>=8) throw new Failure(429,"会话数已达上限，请重启本地页面服务");
        code="";String token=random();sessions.put(token,now+8*60*60*1000L);
        return Map.of("schemaVersion",1,"token",token);
    }
    private synchronized void authenticate(String bearer) {
        if(bearer==null||!bearer.startsWith("Bearer ")||sessions.getOrDefault(bearer.substring(7),0L)<=System.currentTimeMillis())
            throw new Failure(401,"请使用终端中的一次性连接码打开工作台");
    }
    private List<Object> others() throws Exception {
        var result=new ArrayList<Object>();CliState.checkPrivate(CliState.root());
        try(var files=Files.newDirectoryStream(CliState.root(),"*.json")) {
            int count=0;
            for(var file:files) {
                if(++count>256) throw new Failure(409,"本地状态文件过多，请检查状态目录");
                try {
                    CliState.checkPrivate(file);if(Files.size(file)>1024*1024)continue;
                    var data=UiConfig.JSON.readTree(Files.readString(file));
                    long pid=data.path("pid").asLong(),age=System.currentTimeMillis()-data.path("updatedAtUnixMs").asLong();
                    String config=data.path("configPath").asText();
                    boolean matches=System.getProperty("os.name").startsWith("Windows")?config.equalsIgnoreCase(options.config().toString()):config.equals(options.config().toString());
                    if(pid==ProcessHandle.current().pid()||age<0||age>5000||!matches||data.path("schemaVersion").asInt()!=1||ProcessHandle.of(pid).filter(ProcessHandle::isAlive).isEmpty())continue;
                    result.add(Map.of("pid",pid,"phase",data.path("phase").asText(),"controlAuthenticated",data.path("controlAuthenticated").asBoolean(),
                            "businessReady",data.path("businessReady").asBoolean(),"readOnly",true));
                } catch(NoSuchFileException|com.fasterxml.jackson.core.JsonProcessingException ignored) { }
            }
        }
        return result;
    }
    private Object api(String path,String method,JsonNode body) throws Exception {
        synchronized(operations) {
            if(path.equals("/api/config")&&method.equals("GET")) return UiConfig.view(options.config());
            if(path.equals("/api/status")&&method.equals("GET")) {
                List<Object> others=List.of();String warning="";
                try {others=others();} catch(Exception error) {warning="无法安全读取其他实例状态，连接操作已禁用";}
                return Map.of("schemaVersion",1,"implementation","java","version",version,"configPath",options.config().toString(),
                        "runtime",runtime.snapshot(),"otherInstances",others,"instanceWarning",warning);
            }
            if(Set.of("/api/config/save","/api/config/validate").contains(path)&&method.equals("POST")) {
                var warnings=new ArrayList<String>();String text=UiConfig.prepare(options.config(),body,warnings);
                boolean save=path.endsWith("/save");if(save)UiConfig.save(options.config(),body.path("revision").asText(),text);
                return Map.of("schemaVersion",1,"saved",save,"offline",true,"warnings",warnings);
            }
            if(path.equals("/api/connection")&&method.equals("POST")) {
                String action=body.path("action").asText();
                if(!Set.of("start","stop","restart").contains(action))throw new Failure(400,"未知连接操作");
                if(action.equals("stop")) runtime.stop();
                else {
                    if(!others().isEmpty()) throw new Failure(409,"已有其他 CLI 实例运行，本页只读展示且不会接管");
                    var snapshot=UiConfig.read(options.config());UiConfig.checkRevision(snapshot,body.path("revision").asText());
                    UiConfig.document(snapshot.text());var config=ClientCli.parse(snapshot.text(), ignored -> { });config.setUpdateCheckEnabled(false);
                    if(action.equals("restart")) runtime.stop();
                    runtime.start(config,options.config(),snapshot.revision(),options.loginTimeoutSeconds());
                }
                return Map.of("schemaVersion",1,"accepted",true);
            }
            if(Set.of("/api/config","/api/status","/api/config/save","/api/config/validate","/api/connection").contains(path)) throw new Failure(405,"此接口不支持该方法");
            throw new Failure(404,"接口不存在");
        }
    }
    private void handle(ChannelHandlerContext ctx,String path,String method,HttpHeaders headers,byte[] bytes) {
        int status=200;byte[] result;String type="application/json; charset=utf-8";
        try {
            if(!origin.substring(7).equals(headers.get("Host"))||headers.getAll("Host").size()!=1)throw new Failure(403,"Host 不匹配");
            String requestOrigin=headers.get("Origin");
            if(headers.getAll("Origin").size()>1||requestOrigin!=null&&!origin.equals(requestOrigin)||"cross-site".equals(headers.get("Sec-Fetch-Site")))throw new Failure(403,"仅允许本地页面访问");
            if(!Set.of("GET","POST").contains(method)) throw new Failure(405,"不支持该方法");
            if(path.contains("?")||path.contains("%")) throw new Failure(400,"不支持查询参数或编码路径");
            if(method.equals("POST")) {
                if(!origin.equals(requestOrigin)||!"1".equals(headers.get("X-Specus-UI"))) throw new Failure(403,"写入操作必须来自本地页面");
                if(!headers.get("Content-Type","").split(";",2)[0].trim().equalsIgnoreCase("application/json"))throw new Failure(415,"请求必须是 JSON");
            }
            if(Set.of("/","/app.js","/app.css").contains(path)&&method.equals("GET")) {
                String name=path.equals("/")?"index.html":path.substring(1);
                try(var stream=LocalUi.class.getResourceAsStream("/local-ui/"+name)) {
                    if(stream==null) throw new Failure(404,"页面资源缺失");result=stream.readAllBytes();
                }
                type=path.endsWith(".js")?"text/javascript; charset=utf-8":path.endsWith(".css")?"text/css; charset=utf-8":"text/html; charset=utf-8";
            } else {
                JsonNode body=UiConfig.JSON.createObjectNode();
                if(method.equals("POST")) {
                    try { body=CliOutput.JSON.readTree(bytes);if(body==null||!body.isObject())throw new IllegalArgumentException(); }
                    catch(Exception error) {throw new Failure(400,"无效 JSON 请求");}
                }
                Object data;
                if(path.equals("/api/session")&&method.equals("POST")) data=session(body);
                else {authenticate(headers.get("Authorization"));data=api(path,method,body);}
                result=CliOutput.JSON.writeValueAsBytes(data);
            }
        } catch(Exception error) {
            status=error instanceof Failure failure?failure.status:422;
            String message=error instanceof Failure?error.getMessage():"操作失败，请检查配置、权限和本地状态；原始诊断不会返回浏览器";
            try {result=CliOutput.JSON.writeValueAsBytes(Map.of("schemaVersion",1,"error",message));}
            catch(Exception impossible) {result="{}".getBytes(StandardCharsets.UTF_8);}
        }
        var response=new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,HttpResponseStatus.valueOf(status),Unpooled.wrappedBuffer(result));
        response.headers().set("Content-Type",type).set("Content-Length",result.length).set("Connection","close")
                .set("Cache-Control","no-store").set("X-Content-Type-Options","nosniff").set("Referrer-Policy","no-referrer")
                .set("X-Frame-Options","DENY").set("Permissions-Policy","camera=(), microphone=(), geolocation=()")
                .set("Content-Security-Policy","default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
        ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
    }
    public static int run(ClientCli.Options options,String version) {
        System.setOut(new java.io.PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.out),true,StandardCharsets.UTF_8));
        // No raw core log lines (tokens/session IDs) in a browser-management terminal.
        if(org.slf4j.LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME) instanceof ch.qos.logback.classic.Logger logger)
            logger.setLevel(ch.qos.logback.classic.Level.OFF);
        Path lock=null;Channel listener=null;boolean ownsLock=false;String stage="私有状态目录";
        var group=new MultiThreadIoEventLoopGroup(2,NioIoHandler.newFactory());
        var workers=new ThreadPoolExecutor(0,16,30,TimeUnit.SECONDS,new SynchronousQueue<>(),r -> {var t=new Thread(r,"local-ui-http");t.setDaemon(true);return t;});
        var ui=new LocalUi(options,version);var finished=new CountDownLatch(1);
        var connections=new java.util.concurrent.atomic.AtomicInteger();
        Thread hook=new Thread(finished::countDown,"local-ui-shutdown");
        try {
            lock=CliState.ensureRoot().resolve(CliState.prefix(options.config().toString()).substring(5)+"ui.lock");
            stage="同配置管理锁（先确认原管理进程已退出，再清理遗留锁）";
            Files.writeString(lock,Long.toString(ProcessHandle.current().pid()),StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE);
            ownsLock=true;
            stage="本机端口（检查 --port 是否被占用，或使用 --port 0）";
            listener=new ServerBootstrap().group(group).channel(NioServerSocketChannel.class).childHandler(new ChannelInitializer<SocketChannel>() {
                @Override protected void initChannel(SocketChannel channel) {
                    channel.pipeline().addLast(new ChannelInboundHandlerAdapter() {
                        boolean admitted;
                        io.netty.util.concurrent.ScheduledFuture<?> deadline;
                        @Override public void channelActive(ChannelHandlerContext ctx) {
                            if(connections.incrementAndGet()>16) {connections.decrementAndGet();ctx.close();return;}
                            admitted=true;deadline=ctx.executor().schedule(() -> {ctx.close();},25,TimeUnit.SECONDS);ctx.fireChannelActive();
                        }
                        @Override public void channelInactive(ChannelHandlerContext ctx) {
                            if(admitted) connections.decrementAndGet();if(deadline!=null)deadline.cancel(false);ctx.fireChannelInactive();
                        }
                    });
                    channel.pipeline().addLast(new ReadTimeoutHandler(10),new HttpServerCodec(4096,16384,8192),new HttpObjectAggregator(65536),new SimpleChannelInboundHandler<FullHttpRequest>() {
                        @Override protected void channelRead0(ChannelHandlerContext ctx,FullHttpRequest request) {
                            if(!request.decoderResult().isSuccess()) {ctx.close();return;}
                            byte[] body=new byte[request.content().readableBytes()];request.content().readBytes(body);
                            String path=request.uri(),method=request.method().name();HttpHeaders headers=request.headers().copy();
                            try {workers.execute(() -> ui.handle(ctx,path,method,headers,body));}
                            catch(RejectedExecutionException ignored) {ctx.close();}
                        }
                        @Override public void exceptionCaught(ChannelHandlerContext ctx,Throwable error) {ctx.close();}
                    });
                }
            }).bind(new InetSocketAddress("127.0.0.1",options.uiPort())).sync().channel();
            ui.origin="http://127.0.0.1:"+((InetSocketAddress)listener.localAddress()).getPort();
            stage="管理服务";
            System.out.println("本地管理页面："+ui.origin+"\n配置："+options.config()+"\nCtrl+C 退出管理服务及本页连接。");ui.printCode();
            if(!options.noOpen()) {
                String url=ui.origin+"/#"+ui.code;
                try {
                    String os=System.getProperty("os.name");
                    new ProcessBuilder(os.startsWith("Windows")?List.of("rundll32","url.dll,FileProtocolHandler",url):List.of(os.startsWith("Mac")?"open":"xdg-open",url))
                            .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
                } catch(Exception error) {System.err.println("未能打开浏览器，请手动打开本地地址并输入连接码。");}
            }
            Thread.ofVirtual().start(() -> {try(var reader=new java.io.BufferedReader(new java.io.InputStreamReader(System.in))) {while(reader.readLine()!=null) ui.printCode();} catch(Exception ignored) { }});
            // JVM shutdown hooks must finish cleanup themselves, not merely wake main (which JVM may abandon).
            Path ownedLock=lock;Channel ownedListener=listener;
            hook=new Thread(() -> {ownedListener.close().syncUninterruptibly();synchronized(ui.operations) {try {ui.runtime.stop();Files.deleteIfExists(ownedLock);}catch(Exception ignored) { }}finished.countDown();},"local-ui-shutdown");
            Runtime.getRuntime().addShutdownHook(hook);finished.await();return 0;
        } catch(Exception error) {
            System.err.println("无法启动本地页面："+stage+"。请检查对应资源及当前用户权限。");return 2;
        } finally {
            if(listener!=null)listener.close().syncUninterruptibly();workers.shutdownNow();group.shutdownGracefully(0,2,TimeUnit.SECONDS).syncUninterruptibly();
            try {Runtime.getRuntime().removeShutdownHook(hook);}catch(IllegalStateException ignored) { }
            try {ui.runtime.stop();}catch(Exception ignored) { }
            // CREATE_NEW may fail: never remove another process's lock.
            if(ownsLock&&lock!=null)try {Files.deleteIfExists(lock);}catch(Exception ignored) { }
        }
    }
}
