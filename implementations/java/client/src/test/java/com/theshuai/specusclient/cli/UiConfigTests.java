package com.theshuai.specusclient.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import static org.assertj.core.api.Assertions.*;

class UiConfigTests {
    @TempDir Path temporary;
    @Test void argumentsAreUiOnlyAndBounded() {
        var options=ClientCli.parse(new String[]{"ui","--no-open","--port=8765"});
        assertThat(options.noOpen()).isTrue();assertThat(options.uiPort()).isEqualTo(8765);
        for(var args:List.of(new String[]{"--no-open"},new String[]{"--port=0"},new String[]{"ui","--port=-1"},
                new String[]{"ui","--port=65536"},new String[]{"ui","--port"},new String[]{"ui","--json"},new String[]{"ui","--debug"},new String[]{"ui","--no-update"}))
            assertThatThrownBy(() -> ClientCli.parse(args)).isInstanceOf(IllegalArgumentException.class);
    }
    @Test void editsAreLosslessRedactedValidatedAndConflictChecked() throws Exception {
        Path path=temporary.resolve("config.jsonc");
        String text="/* { 前导注释 */\n{\n // 凭据\n \"apiKey\":\"PRIVATE_KEY\",\"secret\":\"PRIVATE_SECRET\",\n \"serverBaseUrl\":\"http://localhost:1\",\"unknown\":{\"nested\":[1,{\"x\":true}]},\n}\n// 尾部";
        Files.writeString(path,text);String revision=UiConfig.read(path).revision();
        var edit=UiConfig.JSON.readTree("{\"revision\":\""+revision+"\",\"changes\":{\"serverBaseUrl\":\"http://localhost:2\",\"secret\":\"\",\"peerMeshDevice\":\"noop\"}}");
        String prepared=UiConfig.prepare(path,edit,new ArrayList<>());
        assertThat(Files.readString(path)).isEqualTo(text);
        assertThat(prepared).contains("/* { 前导注释 */","// 尾部","\"unknown\":{\"nested\":[1,{\"x\":true}]}","PRIVATE_SECRET");
        UiConfig.save(path,revision,prepared);
        assertThat(UiConfig.JSON.writeValueAsString(UiConfig.view(path))).doesNotContain("PRIVATE_KEY","PRIVATE_SECRET");
        assertThatThrownBy(() -> UiConfig.save(path,revision,prepared)).isInstanceOf(LocalUi.Failure.class).extracting("status").isEqualTo(409);
        CliState.checkPrivate(path);
    }
    @Test void malformedAndAmbiguousDocumentsCannotBeEdited() {
        for(String text:List.of("{\"secret\":\"a\",\"secret\":\"b\"}","{\"Secret\":\"x\"}","{\"secret\":\"a\",\"secr\\u0065t\":\"b\"}","{\"x\":[1}}","{}{}","[]","{\"x\":\"unterminated}"))
            assertThatThrownBy(() -> UiConfig.document(text)).isInstanceOf(Exception.class);
    }
    @Test void unsafeChangesAndPathsAreRejectedWithoutWriting() throws Exception {
        Path path=temporary.resolve("new.jsonc");
        for(String changes:List.of("{\"serverBaseUrl\":\"http://user:pass@localhost\"}","{\"serverBaseUrl\":\"http://localhost/?token=x\"}","{\"peerMeshDevice\":\"tun\"}","{\"unknown\":\"x\"}","{\"secret\":12}")) {
            var edit=UiConfig.JSON.readTree("{\"revision\":\"missing\",\"changes\":"+changes+"}");
            assertThatThrownBy(() -> UiConfig.prepare(path,edit,new ArrayList<>())).isInstanceOf(Exception.class);
        }
        assertThat(Files.exists(path)).isFalse();
        assertThatThrownBy(() -> UiConfig.read(temporary)).isInstanceOf(LocalUi.Failure.class);
    }
}
