import express, { Request, Response } from 'express';

import { AgentIdentityService, ScopeViolationError } from './agents/agentIdentityService';
import { MongoAgentIdentityRepository } from './agents/mongoAgentIdentityRepository';
import { GitHubAuthenticationService } from './auth/github';
import { SessionService } from './auth/session';
import { UserRepository, WebAuthnProvider, WebAuthnService } from './auth/webauthn';
import { GatewayEnvironment, loadGatewayEnvironment } from './config/env';
import { createAuthMiddleware } from './middleware/auth';
import { createWorkloadIdentityMiddleware } from './middleware/workloadIdentity';

export interface GatewayDependencies {
  environment: GatewayEnvironment;
  webAuthn: WebAuthnService;
  github: GitHubAuthenticationService;
  sessions: SessionService;
  agents: AgentIdentityService;
  enforceWorkloadIdentity: boolean;
}

function sessionResponse(user: { id: string; email: string; roles: string[] }, authMethod: 'webauthn' | 'github', sessions: SessionService) {
  return sessions.issue({ sub: user.id, email: user.email, roles: user.roles, authMethod });
}

function routeError(response: Response, error: unknown): void {
  if (error instanceof ScopeViolationError) {
    response.status(422).json({ error: error.message });
    return;
  }
  response.status(400).json({ error: error instanceof Error ? error.message : 'invalid_request' });
}

export function createGatewayApp(dependencies: GatewayDependencies) {
  const app = express();
  app.use(express.json({ limit: '64kb' }));

  app.post('/auth/webauthn/register/options', async (request: Request, response: Response) => {
    try {
      response.json({ options: await dependencies.webAuthn.beginRegistration(request.body.email, request.body.displayName) });
    } catch (error) {
      routeError(response, error);
    }
  });

  app.post('/auth/webauthn/register/verify', async (request: Request, response: Response) => {
    try {
      const user = await dependencies.webAuthn.completeRegistration(request.body.email, request.body.response);
      response.status(201).json({ user: { id: user.id, email: user.email } });
    } catch (error) {
      routeError(response, error);
    }
  });

  app.post('/auth/webauthn/authenticate/options', async (request: Request, response: Response) => {
    try {
      response.json({ options: await dependencies.webAuthn.beginAuthentication(request.body.email) });
    } catch (error) {
      routeError(response, error);
    }
  });

  app.post('/auth/webauthn/authenticate/verify', async (request: Request, response: Response) => {
    try {
      const user = await dependencies.webAuthn.completeAuthentication(request.body.email, request.body.response);
      response.json({ token: await sessionResponse(user, 'webauthn', dependencies.sessions) });
    } catch (error) {
      routeError(response, error);
    }
  });

  app.post('/auth/github/callback', async (request: Request, response: Response) => {
    try {
      const user = await dependencies.github.authenticate(request.body.idToken);
      response.json({ token: await sessionResponse(user, 'github', dependencies.sessions) });
    } catch (error) {
      routeError(response, error);
    }
  });

  app.get('/protected', createAuthMiddleware(dependencies.sessions), (_request, response) => {
    response.json({ session: response.locals.session });
  });

  const agentRouter = express.Router();
  if (dependencies.enforceWorkloadIdentity) {
    agentRouter.use(createWorkloadIdentityMiddleware(dependencies.environment.spiffeTrustDomain));
  }
  agentRouter.post('/', async (request, response) => {
    try {
      response.status(201).json({ agent: await dependencies.agents.create(request.body) });
    } catch (error) {
      routeError(response, error);
    }
  });
  agentRouter.get('/:id', async (request, response) => {
    const agent = await dependencies.agents.getById(request.params.id);
    response.status(agent ? 200 : 404).json(agent ? { agent } : { error: 'agent_not_found' });
  });
  agentRouter.patch('/:id', async (request, response) => {
    try {
      const agent = await dependencies.agents.update(request.params.id, request.body);
      response.status(agent ? 200 : 404).json(agent ? { agent } : { error: 'agent_not_found' });
    } catch (error) {
      routeError(response, error);
    }
  });
  agentRouter.delete('/:id', async (request, response) => {
    response.status((await dependencies.agents.delete(request.params.id)) ? 204 : 404).send();
  });
  app.use('/api/agents', agentRouter);

  return app;
}

export function createProductionGatewayApp(
  environment: GatewayEnvironment,
  webAuthn: WebAuthnProvider,
  users: UserRepository,
  github: GitHubAuthenticationService,
) {
  return createGatewayApp({
    environment,
    webAuthn: new WebAuthnService(users, webAuthn),
    github,
    sessions: new SessionService(environment.sessionJweKeyBase64, environment.sessionTtlSeconds),
    agents: new AgentIdentityService(new MongoAgentIdentityRepository()),
    enforceWorkloadIdentity: true,
  });
}

export { loadGatewayEnvironment };
