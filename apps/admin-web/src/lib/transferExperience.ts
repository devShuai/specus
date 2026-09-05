/** Discovery is not membership. Collaboration always requires an explicit shared space. */
export function collaborationPeers<T extends { sameRoom?: boolean }>(peers: readonly T[], sharedSpace: boolean): T[] {
  return sharedSpace ? peers.filter((peer) => peer.sameRoom === true) : [];
}

export function keepUncompletedTransfers<T extends { status: string }>(items: readonly T[]): T[] {
  return items.filter((item) => item.status !== "completed");
}

export function clipboardQuickSendAllowed(enabled: boolean, canSend: boolean, targetPeerId: string): boolean {
  return enabled && canSend && Boolean(targetPeerId);
}

export function transferCompletionLabel(cloud: boolean): string {
  return cloud ? "文件链接已生成" : "对方已接收";
}
