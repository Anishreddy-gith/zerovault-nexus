import { SessionClaims, SessionService } from '@zerovault/auth-shared';
import { NextFunction, Request, Response } from 'express';

declare global {
  namespace Express {
    interface Locals {
      session?: SessionClaims;
    }
  }
}

export function createSessionAuthMiddleware(sessionService: SessionService) {
  return async (request: Request, response: Response, next: NextFunction): Promise<void> => {
    const authorization = request.header('authorization');
    if (!authorization?.startsWith('Bearer ')) {
      response.status(401).json({ error: 'authentication_required' });
      return;
    }
    try {
      response.locals.session = await sessionService.verify(authorization.slice('Bearer '.length));
      next();
    } catch {
      response.status(401).json({ error: 'invalid_or_expired_session' });
    }
  };
}
