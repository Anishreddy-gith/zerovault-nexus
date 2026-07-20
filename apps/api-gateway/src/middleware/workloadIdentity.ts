import { NextFunction, Request, Response } from 'express';
import { TLSSocket } from 'node:tls';

export interface WorkloadIdentity {
  spiffeId: string;
}

function spiffeIdFromPeerCertificate(socket: TLSSocket): string | null {
  const certificate = socket.getPeerCertificate();
  if (!certificate || !certificate.subjectaltname) {
    return null;
  }
  const uriSan = certificate.subjectaltname
    .split(',')
    .map((entry) => entry.trim())
    .find((entry) => entry.startsWith('URI:'));
  return uriSan?.slice('URI:'.length) ?? null;
}

export function createWorkloadIdentityMiddleware(trustDomain: string) {
  return (request: Request, response: Response, next: NextFunction): void => {
    const socket = request.socket as TLSSocket;
    const spiffeId = typeof socket.getPeerCertificate === 'function' ? spiffeIdFromPeerCertificate(socket) : null;
    if (!spiffeId || !spiffeId.startsWith(`spiffe://${trustDomain}/`)) {
      response.status(401).json({ error: 'valid_spiffe_workload_identity_required' });
      return;
    }
    response.locals.workloadIdentity = { spiffeId } satisfies WorkloadIdentity;
    next();
  };
}
