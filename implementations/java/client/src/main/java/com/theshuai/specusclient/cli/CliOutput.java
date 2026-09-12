package com.theshuai.specusclient.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.theshuai.specusclient.bean.ClientStartupConfig;
import java.net.URI;
import java.util.LinkedHashMap;

public final class CliOutput {
    public static final ObjectMapper JSON = new ObjectMapper();
    private CliOutput() { }
    public static int result(boolean json, String command, int code, Object data, String message) {
        if(command.equals("show")||command.equals("validate")) command="config "+command;
        if (json) {
            var envelope = new LinkedHashMap<String,Object>();
            envelope.put("schemaVersion",1); envelope.put("command",command); envelope.put("ok",code==0);
            envelope.put("exitCode",code); envelope.put("data",data); envelope.put("error",code==0 ? null : message);
            try { System.out.println(JSON.writeValueAsString(envelope)); }
            catch (java.io.IOException error) { throw new IllegalStateException("Cannot encode CLI output"); }
        } else if (code==0) System.out.println(message); else System.err.println(message);
        return code;
    }
    public static String safeUrl(String value) {
        try {
            URI u = URI.create(value.trim());
            return new URI(u.getScheme(),null,u.getHost(),u.getPort(),u.getPath(),null,null).toString();
        } catch (Exception error) { return "<invalid>"; }
    }
    public static ObjectNode redactedConfig(ClientStartupConfig config) {
        ObjectNode node = JSON.valueToTree(config);
        node.put("apiKey","<redacted>"); node.put("secret","<redacted>"); node.put("serverBaseUrl",safeUrl(config.getServerBaseUrl()));
        return node;
    }

    public static String stateSummary(String command, Object result) {
        com.fasterxml.jackson.databind.JsonNode data=JSON.valueToTree(result);
        var text=new StringBuilder();
        for(var row:data.path("instances")) {
            text.append("PID ").append(row.path("pid").asLong()).append(" | ").append(row.path("phase").asText()).append('\n');
            if(command.equals("status")) text.append("  control authenticated: ").append(row.path("controlAuthenticated"))
                    .append(" | forwarding ready: ").append(row.path("businessReady")).append(" (targets not probed)\n");
            else if(command.equals("egress")) {
                // Its own branch because the egress section is an object rather than a list, and
                // because what a person needs from it is the problems rather than an item per entry.
                for(String line:EgressView.lines(row.path("egress"))) text.append(line).append('\n');
            }
            else {
                if(row.path(command).isEmpty()) text.append("  No entries. Check status for channel readiness.\n");
                for(var item:row.path(command)) {
                    if(command.equals("peers")) text.append("  ").append(item.path("clientName")).append(" | ").append(item.path("virtualIp")).append(" | online=").append(item.path("online"));
                    else text.append("  ").append(item.path("name")).append(" | ").append(item.path("application")).append(" | ").append(item.path("accessTarget")).append(" | available=").append(item.path("available"));
                    text.append('\n');
                }
            }
        }
        return text.toString().stripTrailing();
    }
}
