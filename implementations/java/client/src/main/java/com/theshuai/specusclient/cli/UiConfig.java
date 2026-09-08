package com.theshuai.specusclient.cli;

import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.security.MessageDigest;
import java.util.*;

/** Lossless top-level edits. Offsets are taken from the same JSONC tokenizer used for validation. */
final class UiConfig {
    static final Set<String> FIELDS = Set.of("serverBaseUrl", "apiKey", "secret", "peerMeshDevice");
    static final JsonMapper JSON = JsonMapper.builder().enable(JsonReadFeature.ALLOW_JAVA_COMMENTS,
            JsonReadFeature.ALLOW_TRAILING_COMMA, JsonReadFeature.ALLOW_YAML_COMMENTS).build();
    record Snapshot(String text, String revision) { }
    record Span(int start, int end) { }
    record Document(JsonNode raw, Map<String,Span> spans, int opening) { }
    static LocalUi.Failure invalid() { return new LocalUi.Failure(422,"无法安全编辑配置，请使用外部编辑器检查语法、重复字段和权限"); }
    static Snapshot read(Path path) throws Exception {
        for (Path p=path;p!=null;p=p.getParent()) {
            if (p.equals(path) && !Files.exists(p, LinkOption.NOFOLLOW_LINKS)) continue;
            var attrs=Files.readAttributes(p,BasicFileAttributes.class,LinkOption.NOFOLLOW_LINKS);
            if (attrs.isSymbolicLink() || attrs.isOther() || p.equals(path) && !attrs.isRegularFile()) throw invalid();
        }
        if (!Files.exists(path)) return new Snapshot("{}","missing");
        byte[] bytes;
        try(var input=Files.newInputStream(path)) { bytes=input.readNBytes(1024*1024+1); }
        if(bytes.length>1024*1024) throw invalid();
        // Reject malformed UTF-8 instead of silently replacing bytes during a save.
        String text=StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(bytes)).toString();
        return new Snapshot(text,HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)));
    }
    static Document document(String text) throws Exception {
        var spans=new LinkedHashMap<String,Span>();
        try(var parser=JSON.createParser(text)) {
            if(parser.nextToken()!=JsonToken.START_OBJECT) throw invalid();
            int opening=(int)parser.currentTokenLocation().getCharOffset();
            while(parser.nextToken()!=JsonToken.END_OBJECT) {
                if(parser.currentToken()!=JsonToken.FIELD_NAME) throw invalid();
                String key=parser.currentName();
                if(spans.containsKey(key) || FIELDS.stream().anyMatch(f -> f.equalsIgnoreCase(key)&&!f.equals(key))) throw invalid();
                if(parser.nextToken()==null) throw invalid();
                int start=(int)parser.currentTokenLocation().getCharOffset();
                parser.skipChildren(); parser.finishToken();
                spans.put(key,new Span(start,(int)parser.currentLocation().getCharOffset()));
            }
            if(parser.nextToken()!=null) throw invalid();
            return new Document(JSON.readTree(text),spans,opening);
        } catch(JsonProcessingException error) { throw invalid(); }
    }
    static Map<String,Object> view(Path path) throws Exception {
        var snapshot=read(path); var raw=document(snapshot.text()).raw();
        return Map.of("schemaVersion",1,"revision",snapshot.revision(),"exists",!snapshot.revision().equals("missing"),
                "configPath",path.toString(),"fields",Map.of("serverBaseUrl",CliOutput.safeUrl(raw.path("serverBaseUrl").asText("")),
                "peerMeshDevice",raw.path("peerMeshDevice").asText("noop")),"hasApiKey",!raw.path("apiKey").asText("").isBlank(),
                "hasSecret",!raw.path("secret").asText("").isBlank(),"editableFields",FIELDS);
    }
    static String prepare(Path path, JsonNode edit, List<String> warnings) throws Exception {
        var snapshot=read(path); checkRevision(snapshot,edit.path("revision").asText());
        var doc=document(snapshot.text()); var changes=edit.path("changes");
        if(!changes.isObject()) throw invalid();
        record Replacement(int start,int end,String value) { }
        var replacements=new ArrayList<Replacement>(); var additions=new ArrayList<String>();
        for(var entry:changes.properties()) {
            String key=entry.getKey();
            if(!FIELDS.contains(key)||!entry.getValue().isTextual()) throw invalid();
            String value=entry.getValue().asText();
            if((key.equals("apiKey")||key.equals("secret"))&&value.isBlank()) continue;
            if(key.equals("serverBaseUrl")) {
                var uri=java.net.URI.create(value);
                if(!Set.of("http","https").contains(uri.getScheme())||uri.getHost()==null||uri.getRawUserInfo()!=null||uri.getRawQuery()!=null||uri.getRawFragment()!=null) throw invalid();
            }
            if(key.equals("peerMeshDevice")&&!Set.of("noop","auto").contains(value)) throw invalid();
            String quoted=JSON.writeValueAsString(value); var span=doc.spans().get(key);
            if(span==null) additions.add(JSON.writeValueAsString(key)+": "+quoted);
            else replacements.add(new Replacement(span.start(),span.end(),quoted));
        }
        if(!additions.isEmpty()) replacements.add(new Replacement(doc.opening()+1,doc.opening()+1,
                "\n  "+String.join(",\n  ",additions)+(doc.spans().isEmpty()?"\n":",")));
        replacements.sort(Comparator.comparingInt(Replacement::start).reversed());
        var result=new StringBuilder(snapshot.text());
        for(var change:replacements) result.replace(change.start(),change.end(),change.value());
        String text=result.toString();
        if(text.getBytes(StandardCharsets.UTF_8).length>1024*1024) throw invalid();
        ClientCli.parse(text,warnings::add);
        return text;
    }
    static void checkRevision(Snapshot snapshot,String revision) {
        if(!snapshot.revision().equals(revision)) throw new LocalUi.Failure(409,"配置已被修改，请重新载入后再操作");
    }
    static void save(Path path,String revision,String text) throws Exception {
        checkRevision(read(path),revision);
        if(Files.exists(path)) {
            if(CliState.posix() && !Files.getPosixFilePermissions(path).contains(PosixFilePermission.OWNER_WRITE)) throw invalid();
            var dos=Files.getFileAttributeView(path,DosFileAttributeView.class);
            if(dos!=null&&dos.readAttributes().isReadOnly()) throw invalid();
        }
        Path dir=CliState.posix()?Files.createTempDirectory(path.getParent(),".specus-ui-save-",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
                :Files.createTempDirectory(path.getParent(),".specus-ui-save-");
        Path temp=dir.resolve("config");
        try {
            if(!CliState.posix()) Files.getFileAttributeView(dir,AclFileAttributeView.class).setAcl(List.of(AclEntry.newBuilder()
                    .setType(AclEntryType.ALLOW).setPrincipal(Files.getOwner(dir)).setPermissions(EnumSet.allOf(AclEntryPermission.class))
                    .setFlags(AclEntryFlag.DIRECTORY_INHERIT,AclEntryFlag.FILE_INHERIT).build()));
            CliState.checkPrivate(dir);
            if(CliState.posix()) Files.createFile(temp,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            try(var out=java.nio.channels.FileChannel.open(temp,StandardOpenOption.CREATE,StandardOpenOption.WRITE)) {
                var buffer=StandardCharsets.UTF_8.encode(text); while(buffer.hasRemaining()) out.write(buffer); out.force(true);
            }
            checkRevision(read(path),revision);
            Files.move(temp,path,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
        } finally { Files.deleteIfExists(temp); Files.deleteIfExists(dir); }
    }
}
