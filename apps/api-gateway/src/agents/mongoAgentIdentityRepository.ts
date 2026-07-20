import mongoose, { InferSchemaType, Schema } from 'mongoose';

import { AgentIdentity, AgentIdentityRepository } from './agentIdentityService';

const agentIdentitySchema = new Schema(
  {
    name: { type: String, required: true, trim: true },
    spiffeId: { type: String, required: true, unique: true },
    parentId: { type: String },
    toolScope: { type: [String], required: true, default: [] },
    createdBy: { type: String, required: true },
    active: { type: Boolean, required: true, default: true },
  },
  { collection: 'agent_identities', timestamps: true },
);

type MongoAgent = InferSchemaType<typeof agentIdentitySchema> & { _id: mongoose.Types.ObjectId };
const AgentIdentityModel = mongoose.models.GatewayAgentIdentity || mongoose.model('GatewayAgentIdentity', agentIdentitySchema);

function serialize(document: MongoAgent): AgentIdentity {
  return {
    id: document._id.toString(),
    name: document.name,
    spiffeId: document.spiffeId,
    parentId: document.parentId ?? undefined,
    toolScope: document.toolScope,
    createdBy: document.createdBy,
    active: document.active,
  };
}

export class MongoAgentIdentityRepository implements AgentIdentityRepository {
  public async create(agent: Omit<AgentIdentity, 'id'>): Promise<AgentIdentity> {
    return serialize((await AgentIdentityModel.create(agent)).toObject() as MongoAgent);
  }

  public async getById(id: string): Promise<AgentIdentity | null> {
    if (!mongoose.isObjectIdOrHexString(id)) {
      return null;
    }
    const document = await AgentIdentityModel.findById(id).lean<MongoAgent>();
    return document ? serialize(document) : null;
  }

  public async update(id: string, update: Pick<AgentIdentity, 'name' | 'toolScope' | 'active'>): Promise<AgentIdentity | null> {
    if (!mongoose.isObjectIdOrHexString(id)) {
      return null;
    }
    const document = await AgentIdentityModel.findByIdAndUpdate(id, update, { new: true }).lean<MongoAgent>();
    return document ? serialize(document) : null;
  }

  public async delete(id: string): Promise<boolean> {
    if (!mongoose.isObjectIdOrHexString(id)) {
      return false;
    }
    return (await AgentIdentityModel.deleteOne({ _id: id })).deletedCount === 1;
  }
}
