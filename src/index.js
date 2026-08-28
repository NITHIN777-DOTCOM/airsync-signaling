import { createSignalingServer } from './server.js';
import { log } from './logger.js';
import { hasMeteredApiKey, hasStaticTurnCredentials, hasAnyTurnCredentialSource } from './config.js';

const server = createSignalingServer();

await server.listen();

if (hasAnyTurnCredentialSource()) {
  log.info('turn_credentials_source', {
    dynamic: hasMeteredApiKey(),
    staticFallback: hasStaticTurnCredentials()
  });
} else {
  log.warn('turn_credentials_missing', {
    detail:
      'Neither METERED_API_KEY nor TURN_USERNAME/TURN_PASSWORD are set. ' +
      'GET /turn-credentials will return the STUN entry only. Signaling and ' +
      'direct/STUN P2P still work; relayed (TURN) fallback does not until a ' +
      'credential source is configured.'
  });
}

let shuttingDown = false;

/**
 * Railway sends SIGTERM before replacing a container. Closing sockets with an explicit
 * shutdown code lets clients tell "the signaling server went away" apart from "my peer
 * went away" and reconnect instead of treating it as a peer disconnect.
 */
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  log.info('shutdown_start', { signal });
  try {
    await server.close();
  } catch (err) {
    log.error('shutdown_error', { error: err.message });
  }
  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

process.on('uncaughtException', (err) => {
  log.error('uncaught_exception', { error: err.message, stack: err.stack });
});

process.on('unhandledRejection', (reason) => {
  log.error('unhandled_rejection', { reason: String(reason) });
});
