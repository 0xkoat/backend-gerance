import type { ModuleEndpoint } from '../generated/prisma/client';

// The URL a launch redirects to, or null while the endpoint isn't configured.
// IPv6 literals need brackets in a URL (http://[fd00::5]:8443/).
export function buildModuleUrl(
  endpoint: Pick<ModuleEndpoint, 'protocol' | 'host' | 'port' | 'path'>,
): string | null {
  if (!endpoint.host || !endpoint.port) {
    return null;
  }
  const host = endpoint.host.includes(':')
    ? `[${endpoint.host}]`
    : endpoint.host;
  return `${endpoint.protocol.toLowerCase()}://${host}:${endpoint.port}${endpoint.path}`;
}
