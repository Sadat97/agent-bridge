// Retention (DESIGN.md section 4.1): ciphertext lives 30 days, unclaimed
// Welcomes 7 days. A member whose fetch cursor is behind what was deleted can
// no longer follow the group's commits, so it is marked stale and the topic
// owner is told to re-add it.

import type { RelayContext } from './context.ts';
import { withTransaction } from './db.ts';

export interface RetentionResult {
  prunedTopics: number;
  staleMembers: Array<{ topicId: string; deviceId: string }>;
  welcomesDeleted: number;
  keyPackagesDeleted: number;
  challengesDeleted: number;
}

export async function runRetention(ctx: RelayContext): Promise<RetentionResult> {
  const now = ctx.now();
  const cutoff = new Date(now.getTime() - ctx.config.retentionDays * 86_400_000);

  const { prunedTopics, staleMembers } = await withTransaction(ctx.pool, async (db) => {
    // Prune by seq, not just timestamp, so each topic keeps a contiguous suffix.
    const pruned = await db.query(
      `WITH cutoff AS (
         SELECT topic_id, max(seq) AS max_seq FROM mls_messages WHERE created_at < $1 GROUP BY topic_id
       ), deleted AS (
         DELETE FROM mls_messages m USING cutoff c WHERE m.topic_id = c.topic_id AND m.seq <= c.max_seq
       )
       UPDATE topics t SET pruned_through_seq = GREATEST(t.pruned_through_seq, c.max_seq)
         FROM cutoff c WHERE t.id = c.topic_id`,
      [cutoff],
    );

    const stale = await db.query<{ topic_id: string; device_id: string }>(
      `UPDATE topic_members m SET stale_at = $1
         FROM topics t
        WHERE t.id = m.topic_id AND m.removed_at IS NULL AND m.stale_at IS NULL
          AND m.last_fetched_seq < t.pruned_through_seq
       RETURNING m.topic_id, m.device_id`,
      [now],
    );
    return {
      prunedTopics: pruned.rowCount ?? 0,
      staleMembers: stale.rows.map((r) => ({ topicId: r.topic_id, deviceId: r.device_id })),
    };
  });

  // Tell each topic owner's devices which members need re-adding.
  for (const { topicId, deviceId } of staleMembers) {
    const { rows } = await ctx.pool.query<{ device_id: string }>(
      `SELECT m.device_id FROM topic_members m JOIN topics t ON t.id = m.topic_id
        WHERE m.topic_id = $1 AND m.account_id = t.owner_account AND m.removed_at IS NULL`,
      [topicId],
    );
    ctx.hub.publish(
      rows.map((r) => r.device_id),
      { type: 'member_stale', topic_id: topicId, device_id: deviceId },
    );
  }

  const welcomes = await ctx.pool.query(
    "DELETE FROM welcomes WHERE expires_at < $1 OR acked_at < $1::timestamptz - interval '1 day'",
    [now],
  );
  const keyPackages = await ctx.pool.query(
    "DELETE FROM key_packages WHERE (claimed_at IS NULL AND expires_at < $1) OR claimed_at < $1::timestamptz - interval '7 days'",
    [now],
  );
  const challenges = await ctx.pool.query('DELETE FROM auth_challenges WHERE expires_at < $1', [now]);

  return {
    prunedTopics,
    staleMembers,
    welcomesDeleted: welcomes.rowCount ?? 0,
    keyPackagesDeleted: keyPackages.rowCount ?? 0,
    challengesDeleted: challenges.rowCount ?? 0,
  };
}
