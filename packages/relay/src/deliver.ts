// Fan-out that re-checks the two ways a socket stops being allowed to listen:
// its access token has expired, or its device has been revoked. Expired sockets
// are closed individually (a newer socket for the same device may still be
// valid). A revoked device loses every socket.

import type { RelayContext } from './context.ts';
import type { RelayEvent } from './hub.ts';

export const WS_CLOSE_EXPIRED = 4001;
export const WS_CLOSE_REVOKED = 4003;

export async function deliver(ctx: RelayContext, deviceIds: Iterable<string>, event: RelayEvent): Promise<void> {
  const nowMs = ctx.now().getTime();
  ctx.hub.closeExpired(nowMs, WS_CLOSE_EXPIRED, 'token_expired');
  const connected = [...new Set(deviceIds)].filter((id) => ctx.hub.has(id));
  if (connected.length === 0) return;

  const { rows } = await ctx.pool.query<{ id: string }>(
    'SELECT id FROM devices WHERE id = ANY($1::uuid[]) AND revoked_at IS NULL',
    [connected],
  );
  const allowed = new Set(rows.map((row) => row.id));
  for (const id of connected) {
    if (!allowed.has(id)) ctx.hub.closeDevice(id, WS_CLOSE_REVOKED, 'device_revoked');
  }
  ctx.hub.publish(
    connected.filter((id) => allowed.has(id)),
    event,
  );
}
