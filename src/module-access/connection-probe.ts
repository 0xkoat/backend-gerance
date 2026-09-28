import { Injectable } from '@nestjs/common';
import { connect } from 'node:net';

export interface ProbeResult {
  reachable: boolean;
  latencyMs?: number;
  error?: string;
}

const PROBE_TIMEOUT_MS = 3000;

// Plain TCP connect to a module endpoint: answers "is something listening at
// host:port from where the backend runs", nothing more — no request is sent
// and no response body is read or returned. Its own injectable so tests don't
// open real sockets.
@Injectable()
export class ConnectionProbe {
  probe(host: string, port: number): Promise<ProbeResult> {
    return new Promise((resolve) => {
      const startedAt = Date.now();
      const socket = connect({ host, port });
      socket.setTimeout(PROBE_TIMEOUT_MS);

      socket.once('connect', () => {
        const latencyMs = Date.now() - startedAt;
        socket.destroy();
        resolve({ reachable: true, latencyMs });
      });
      socket.once('timeout', () => {
        socket.destroy();
        resolve({
          reachable: false,
          error: `No answer within ${PROBE_TIMEOUT_MS} ms`,
        });
      });
      socket.once('error', (error: NodeJS.ErrnoException) => {
        socket.destroy();
        resolve({ reachable: false, error: error.code ?? error.message });
      });
    });
  }
}
