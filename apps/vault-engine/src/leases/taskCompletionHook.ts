import { LeaseManager } from './leaseManager';

export class TaskCompletionHook {
  public constructor(private readonly leases: LeaseManager) {}

  public complete(jti: string, subject: string): Promise<'completed' | 'not_found' | 'not_task_lease'> {
    return this.leases.complete(jti, subject);
  }
}
