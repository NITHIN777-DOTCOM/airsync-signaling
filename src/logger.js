import { config } from './config.js';

/**
 * Minimal structured (JSON-per-line) logger — the shape Fly.io's log shipper and most
 * aggregators expect, with no dependency.
 *
 * Deliberate policy: this logger is only ever handed *metadata* — fingerprints,
 * connection ids, states, byte counts, close codes. Relayed payloads never reach it.
 * The relay pipe in server.js forwards buffers without reading them, so there is no
 * code path that could log file contents.
 */

const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };
const threshold = LEVELS[config.logLevel] ?? LEVELS.info;

function emit(level, event, fields = {}) {
  if ((LEVELS[level] ?? LEVELS.info) > threshold) return;
  const line = {
    ts: new Date().toISOString(),
    level,
    event,
    ...fields
  };
  const out = level === 'error' || level === 'warn' ? process.stderr : process.stdout;
  out.write(`${JSON.stringify(line)}\n`);
}

export const log = {
  error: (event, fields) => emit('error', event, fields),
  warn: (event, fields) => emit('warn', event, fields),
  info: (event, fields) => emit('info', event, fields),
  debug: (event, fields) => emit('debug', event, fields)
};
