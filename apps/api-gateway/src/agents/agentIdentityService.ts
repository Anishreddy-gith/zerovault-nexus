export interface AgentIdentity {
  id: string;
  name: string;
  spiffeId: string;
  parentId?: string;
  toolScope: string[];
  createdBy: string;
  active: boolean;
}

export interface AgentIdentityRepository {
  create(agent: Omit<AgentIdentity, 'id'>): Promise<AgentIdentity>;
  getById(id: string): Promise<AgentIdentity | null>;
  update(id: string, update: Pick<AgentIdentity, 'name' | 'toolScope' | 'active'>): Promise<AgentIdentity | null>;
  delete(id: string): Promise<boolean>;
}

export class ScopeViolationError extends Error {}

function isScopeSubset(childScope: string[], parentScope: string[]): boolean {
  return childScope.every((tool) => parentScope.includes(tool));
}

export class AgentIdentityService {
  public constructor(private readonly repository: AgentIdentityRepository) {}

  public async create(agent: Omit<AgentIdentity, 'id'>): Promise<AgentIdentity> {
    if (agent.parentId) {
      const parent = await this.repository.getById(agent.parentId);
      if (!parent) {
        throw new Error('Parent agent identity was not found');
      }
      if (!isScopeSubset(agent.toolScope, parent.toolScope)) {
        throw new ScopeViolationError('A child agent toolScope must be a subset of its parent toolScope');
      }
    }
    return this.repository.create({ ...agent, toolScope: [...new Set(agent.toolScope)] });
  }

  public getById(id: string): Promise<AgentIdentity | null> {
    return this.repository.getById(id);
  }

  public async update(
    id: string,
    update: Pick<AgentIdentity, 'name' | 'toolScope' | 'active'>,
  ): Promise<AgentIdentity | null> {
    const existing = await this.repository.getById(id);
    if (!existing) {
      return null;
    }
    if (existing.parentId) {
      const parent = await this.repository.getById(existing.parentId);
      if (!parent || !isScopeSubset(update.toolScope, parent.toolScope)) {
        throw new ScopeViolationError('An agent toolScope must remain a subset of its parent toolScope');
      }
    }
    return this.repository.update(id, { ...update, toolScope: [...new Set(update.toolScope)] });
  }

  public delete(id: string): Promise<boolean> {
    return this.repository.delete(id);
  }
}
