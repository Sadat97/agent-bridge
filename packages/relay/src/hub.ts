// In-process fan-out of WebSocket events to connected devices. The relay is a
// single process in MVP; running several would need Postgres LISTEN/NOTIFY here.

export type RelayEvent =
  | {
      type: 'message';
      topic_id: string;
      seq: number;
      epoch: number;
      content: 'commit' | 'application';
      sender_device: string;
      /** base64 MLSMessage, present when small enough to push inline. */
      message?: string;
    }
  | { type: 'welcome'; id: string; topic_id: string; commit_seq: number }
  | { type: 'member_stale'; topic_id: string; device_id: string }
  | { type: 'key_packages_low'; count: number };

export interface EventSocket {
  readonly readyState: number;
  send(data: string): void;
  close(code?: number, reason?: string): void;
}

interface TrackedSocket {
  socket: EventSocket;
  /** Unix milliseconds. The socket is closed once `now` reaches this. */
  expiresAtMs: number;
}

const OPEN = 1;

export class Hub {
  #sockets = new Map<string, Set<TrackedSocket>>();

  add(deviceId: string, socket: EventSocket, expiresAtMs: number): void {
    let set = this.#sockets.get(deviceId);
    if (!set) this.#sockets.set(deviceId, (set = new Set()));
    set.add({ socket, expiresAtMs });
  }

  has(deviceId: string): boolean {
    return (this.#sockets.get(deviceId)?.size ?? 0) > 0;
  }

  socketCount(deviceId: string): number {
    return this.#sockets.get(deviceId)?.size ?? 0;
  }

  remove(deviceId: string, socket: EventSocket): void {
    const set = this.#sockets.get(deviceId);
    if (!set) return;
    for (const entry of set) {
      if (entry.socket === socket) {
        set.delete(entry);
        break;
      }
    }
    if (set.size === 0) this.#sockets.delete(deviceId);
  }

  /** Closes one socket. A newer connection for the same device stays up. */
  closeSocket(deviceId: string, socket: EventSocket, code: number, reason: string): void {
    this.remove(deviceId, socket);
    try {
      socket.close(code, reason);
    } catch {
      // Already closed.
    }
  }

  /** Closes every socket for a device (revocation). */
  closeDevice(deviceId: string, code: number, reason: string): void {
    const set = this.#sockets.get(deviceId);
    if (!set) return;
    const entries = [...set];
    this.#sockets.delete(deviceId);
    for (const entry of entries) {
      try {
        entry.socket.close(code, reason);
      } catch {
        // Already closed.
      }
    }
  }

  /** Closes sockets whose access token has expired. Per socket, not per device. */
  closeExpired(nowMs: number, code: number, reason: string): void {
    const expired: Array<{ deviceId: string; socket: EventSocket }> = [];
    for (const [deviceId, set] of this.#sockets) {
      for (const entry of set) {
        if (entry.expiresAtMs <= nowMs) expired.push({ deviceId, socket: entry.socket });
      }
    }
    for (const entry of expired) this.closeSocket(entry.deviceId, entry.socket, code, reason);
  }

  publish(deviceIds: Iterable<string>, event: RelayEvent): void {
    const data = JSON.stringify(event);
    for (const deviceId of new Set(deviceIds)) {
      for (const entry of this.#sockets.get(deviceId) ?? []) {
        if (entry.socket.readyState !== OPEN) continue;
        try {
          entry.socket.send(data);
        } catch {
          // A broken socket is cleaned up by its close handler.
        }
      }
    }
  }

  get connectedDevices(): number {
    return this.#sockets.size;
  }
}
