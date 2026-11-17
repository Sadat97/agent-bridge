import type { RelayConfig } from './config.ts';
import type { Pool } from './db.ts';
import type { Hub } from './hub.ts';

export interface RelayContext {
  config: RelayConfig;
  pool: Pool;
  hub: Hub;
  /** Injectable clock, for expiry and retention tests. */
  now: () => Date;
}
