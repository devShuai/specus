package com.theshuai.specusclient.peer.portmap;

/**
 * NAT 端口映射协商过程中可恢复的失败。各 mapper 实现把底层异常（IO、协议、解析）统一包成这个。
 *
 * <p>抛出后调用方一般的处理是：「这个协议失败，换下一个；都失败就退回 STUN/打洞」。不要级联 throw，
 * 端口映射只是一个加速/兜底手段，不存在「映射失败 = 业务失败」的关系。
 */
public class PortMappingException extends Exception {

    public PortMappingException(String message) {
        super(message);
    }

    public PortMappingException(String message, Throwable cause) {
        super(message, cause);
    }
}
