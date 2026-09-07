package com.theshuai.specusclient.cli;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Supplier;

/** Owner-only, versioned, atomic read-only snapshots. No listener or login in query commands. */
public final class CliState implements AutoCloseable {
    private final Path root, file;
    private final String config;
    private final ScheduledExecutorService publisher;
    private volatile boolean closed;
    private volatile Supplier<Map<String,Object>> snapshot = () -> new LinkedHashMap<>(Map.of(
            "phase","http-login","controlAuthenticated",false,"businessReady",false,"peers",List.of(),"services",List.of()));
    public CliState(Path config) throws IOException {
        this.config=config.toAbsolutePath().normalize().toString(); root=root();
        if (!Files.exists(root,LinkOption.NOFOLLOW_LINKS)) {
            if (posix()) Files.createDirectory(root,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            else {
                Files.createDirectory(root);
                var view=Files.getFileAttributeView(root,AclFileAttributeView.class);
                if(view==null) throw new IOException("Filesystem lacks private ACLs");
                view.setAcl(List.of(AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(Files.getOwner(root))
                        .setPermissions(EnumSet.allOf(AclEntryPermission.class)).setFlags(AclEntryFlag.DIRECTORY_INHERIT,AclEntryFlag.FILE_INHERIT).build()));
            }
        }
        checkPrivate(root);
        file=root.resolve(prefix(this.config)+ProcessHandle.current().pid()+".json");
        write();
        publisher=Executors.newSingleThreadScheduledExecutor(r -> {var t=new Thread(r,"cli-state");t.setDaemon(true);return t;});
        publisher.scheduleWithFixedDelay(() -> {try{write();}catch(Exception error){System.err.println("State publication failed; status will become stale.");publisher.shutdown();}},1,1,TimeUnit.SECONDS);
    }
    public void observe(Supplier<Map<String,Object>> snapshot) { this.snapshot=snapshot; }
    public static Path root() {
        String override=System.getenv("SPECUS_CLI_STATE_DIR");
        return (override==null ? Path.of(System.getProperty("user.home"),".specus-cli") : Path.of(override)).toAbsolutePath().normalize();
    }
    static boolean posix() { return FileSystems.getDefault().supportedFileAttributeViews().contains("posix"); }
    static String prefix(String config) {
        if(System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win")) config=config.toLowerCase(Locale.ROOT);
        try{return "java-"+HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(config.getBytes(StandardCharsets.UTF_8)))+"-";}
        catch(Exception error){throw new IllegalStateException(error);}
    }
    static void checkPrivate(Path path) throws IOException {
        var attrs=Files.readAttributes(path,BasicFileAttributes.class,LinkOption.NOFOLLOW_LINKS);
        if(attrs.isSymbolicLink()||attrs.isOther()) throw new IOException("State must not be a link/reparse point");
        var owner=Files.getOwner(path,LinkOption.NOFOLLOW_LINKS);
        var me=FileSystems.getDefault().getUserPrincipalLookupService().lookupPrincipalByName(System.getProperty("user.name"));
        if(!owner.equals(me)) throw new IOException("State owner mismatch");
        if(posix()) {
            for(var permission:Files.getPosixFilePermissions(path,LinkOption.NOFOLLOW_LINKS))
                if(!permission.name().startsWith("OWNER_")) throw new IOException("State must be owner-only");
        } else {
            var view=Files.getFileAttributeView(path,AclFileAttributeView.class,LinkOption.NOFOLLOW_LINKS);
            if(view==null) throw new IOException("Filesystem lacks private ACLs");
            for(var entry:view.getAcl()) if(entry.type()==AclEntryType.ALLOW&&!entry.principal().equals(me)) throw new IOException("State must be owner-only");
        }
    }
    private synchronized void write() throws IOException {
        if(closed) return;
        var data=new LinkedHashMap<>(snapshot.get());
        data.put("schemaVersion",1);data.put("configPath",config);data.put("pid",ProcessHandle.current().pid());
        data.put("processRunning",true);data.put("updatedAtUnixMs",System.currentTimeMillis());
        data.put("businessReadinessScope","control/data authenticated; target reachability not tested");
        Path temporary=posix() ? Files.createTempFile(root,".state-",".tmp",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
                : Files.createTempFile(root,".state-",".tmp");
        try { Files.writeString(temporary,CliOutput.JSON.writeValueAsString(data));Files.move(temporary,file,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING); }
        finally {Files.deleteIfExists(temporary);}
    }
    @Override public void close() {
        closed=true;
        publisher.shutdownNow();
        synchronized(this){try{Files.deleteIfExists(file);}catch(IOException ignored){}}
    }
    public static int query(ClientCli.Options options) {
        var instances=new ArrayList<Object>();
        try {
            Path root=root();
            if(Files.exists(root,LinkOption.NOFOLLOW_LINKS)) {
                checkPrivate(root);
                try(var files=Files.newDirectoryStream(root,prefix(options.config().toString())+"*.json")) {
                    int count=0;
                    for(Path file:files) {
                        if(++count>256) throw new IOException("Too many state files");
                        try {
                            checkPrivate(file);if(Files.size(file)>1024*1024)continue;
                            var data=CliOutput.JSON.readTree(Files.readString(file));
                            long age=System.currentTimeMillis()-data.path("updatedAtUnixMs").asLong();
                            long pid=data.path("pid").asLong();
                            boolean matching=System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win")
                                    ? data.path("configPath").asText().equalsIgnoreCase(options.config().toString()) : data.path("configPath").asText().equals(options.config().toString());
                            if(age<0||age>5000||data.path("schemaVersion").asInt()!=1||!matching
                                    ||ProcessHandle.of(pid).filter(ProcessHandle::isAlive).isEmpty())continue;
                            instances.add(options.command().equals("status") ? data : Map.of("pid",pid,"phase",data.path("phase"),
                                    "catalogAvailable",data.path("controlAuthenticated"),options.command(),data.path(options.command())));
                        } catch(NoSuchFileException ignored) { }
                        catch(com.fasterxml.jackson.core.JsonProcessingException ignored) { }
                    }
                }
            }
            var result=Map.of("instances",instances);
            return CliOutput.result(options.json(),options.command(),instances.isEmpty()?5:0,result,instances.isEmpty()
                    ? "No fresh running CLI state for this config. No login was attempted." : CliOutput.stateSummary(options.command(),result));
        }catch(Exception error){return CliOutput.result(options.json(),options.command(),2,null,"Unsafe or unreadable local state. Use an owner-only local directory via SPECUS_CLI_STATE_DIR.");}
    }
}
