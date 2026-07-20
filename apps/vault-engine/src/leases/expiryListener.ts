import { LeaseModel } from '../models/Lease';
import { LeaseRedis } from './leaseManager';

interface LeaseExpirySubscriber {
  connect(): Promise<unknown>;
  subscribe(channel: string, listener: (message: string) => void | Promise<void>): Promise<unknown>;
  unsubscribe(channel: string): Promise<unknown>;
  quit(): Promise<unknown>;
}

interface LeaseExpiryRedis extends LeaseRedis {
  configSet(parameter: string, value: string): Promise<unknown>;
  duplicate(): LeaseExpirySubscriber;
}

export class LeaseExpiryListener {
  private subscriber: LeaseExpirySubscriber | null = null;

  public constructor(private readonly redis: LeaseExpiryRedis) {}

  public async start(): Promise<void> {
    await this.redis.configSet('notify-keyspace-events', 'Ex');
    this.subscriber = this.redis.duplicate();
    await this.subscriber.connect();
    await this.subscriber.subscribe('__keyevent@0__:expired', async (key: string) => {
      if (!key.startsWith('lease:')) {
        return;
      }
      await LeaseModel.updateOne(
        { leaseId: key.slice('lease:'.length), status: 'active' },
        { $set: { status: 'expired' } },
      );
    });
  }

  public async stop(): Promise<void> {
    if (this.subscriber) {
      await this.subscriber.unsubscribe('__keyevent@0__:expired');
      await this.subscriber.quit();
      this.subscriber = null;
    }
  }
}
