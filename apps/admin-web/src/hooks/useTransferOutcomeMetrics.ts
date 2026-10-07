import { useCallback, useEffect, useRef, useState } from "react";
import { fetchProductMetricsCollecting, reportTransferOutcomes } from "../api/client";
import {
  readDeviceOptOut,
  trackSendOutcomes,
  TransferOutcomeReporter,
  writeDeviceOptOut,
  type OutgoingSendView,
  type SendAttemptTrack,
} from "../lib/productMetrics";

export interface TransferOutcomeMetrics {
  /** The signed-in member's organisation collects product metrics: show the standing notice. */
  collecting: boolean;
  /** This browser chose not to take part (kept in local storage). */
  optedOut: boolean;
  setOptedOut: (optedOut: boolean) => void;
  /** The temporary-storage upload of a send record started in its current attempt. */
  markCloudStarted: (sendId: string) => void;
  /** A peer connection started carrying a send record's bytes in its current attempt. */
  markEstablished: (sendId: string) => void;
  /** A new attempt of a send record starts: forget what the previous attempt used. */
  startAttempt: (sendId: string) => void;
}

/**
 * Reports the transfer page's finished send attempts (protocol/spec/product-metrics.md section
 * 4.2): only for a signed-in member whose tenant collects and whose browser did not opt out, only
 * the five closed fields, batched, at most once, and silently -- no failure ever reaches the page.
 * Signed out, not collecting or opted out, it sends no request at all.
 */
export function useTransferOutcomeMetrics({ signedIn, sends, peerPath }: {
  signedIn: boolean;
  sends: readonly OutgoingSendView[];
  peerPath: (peerId: string) => "direct" | "turn" | undefined;
}): TransferOutcomeMetrics {
  const [collecting, setCollecting] = useState(false);
  const [recheck, setRecheck] = useState(0);
  const [optedOut, setOptedOutState] = useState(() => readDeviceOptOut());
  const reporterRef = useRef<TransferOutcomeReporter | null>(null);
  if (reporterRef.current === null) {
    reporterRef.current = new TransferOutcomeReporter({
      send: reportTransferOutcomes,
      onStopped: () => setRecheck((value) => value + 1),
    });
  }
  const tracksRef = useRef(new Map<string, SendAttemptTrack>());
  const cloudStartedRef = useRef(new Set<string>());
  const establishedRef = useRef(new Set<string>());
  const peerPathRef = useRef(peerPath);
  peerPathRef.current = peerPath;

  useEffect(() => {
    if (!signedIn) {
      setCollecting(false);
      return undefined;
    }
    let alive = true;
    void fetchProductMetricsCollecting().then((value) => {
      if (alive) setCollecting(value);
    });
    return () => {
      alive = false;
    };
  }, [signedIn, recheck]);

  useEffect(() => {
    reporterRef.current?.setActive(signedIn && collecting && !optedOut);
  }, [signedIn, collecting, optedOut]);

  useEffect(() => {
    const { next, events } = trackSendOutcomes(tracksRef.current, sends, {
      cloudStarted: (id) => cloudStartedRef.current.has(id),
      established: (id) => establishedRef.current.has(id),
      peerPath: (peerId) => peerPathRef.current(peerId),
    });
    tracksRef.current = next;
    for (const event of events) {
      reporterRef.current?.enqueue(event);
    }
  }, [sends]);

  useEffect(() => {
    const reporter = reporterRef.current;
    const flush = () => {
      void reporter?.flush(true);
    };
    window.addEventListener("pagehide", flush);
    return () => {
      window.removeEventListener("pagehide", flush);
      flush();
    };
  }, []);

  const setOptedOut = useCallback((value: boolean) => {
    writeDeviceOptOut(value);
    setOptedOutState(value);
  }, []);
  const markCloudStarted = useCallback((sendId: string) => {
    cloudStartedRef.current.add(sendId);
  }, []);
  const markEstablished = useCallback((sendId: string) => {
    establishedRef.current.add(sendId);
  }, []);
  const startAttempt = useCallback((sendId: string) => {
    cloudStartedRef.current.delete(sendId);
    establishedRef.current.delete(sendId);
  }, []);

  return { collecting: signedIn && collecting, optedOut, setOptedOut, markCloudStarted, markEstablished, startAttempt };
}
