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
}

const OPEN = 1;

export class Hub {
  #sockets = new Map<string, Set<EventSocket>>();

  add(deviceId: string, socket: EventSocket): void {
    let set = this.#sockets.get(deviceId);
    if (!set) this.#sockets.set(deviceId, (set = new Set()));
    set.add(socket);
  }

  remove(deviceId: string, socket: EventSocket): void {
    const set = this.#sockets.get(deviceId);
    if (!set) return;
    set.delete(socket);
    if (set.size === 0) this.#sockets.delete(deviceId);
  }

  publish(deviceIds: Iterable<string>, event: RelayEvent): void {
    const data = JSON.stringify(event);
    for (const deviceId of new Set(deviceIds)) {
      for (const socket of this.#sockets.get(deviceId) ?? []) {
        if (socket.readyState !== OPEN) continue;
        try {
          socket.send(data);
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
