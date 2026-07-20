import { InferSchemaType, model, models, Schema } from 'mongoose';

const agentIdentitySchema = new Schema(
  {
    name: { type: String, required: true, trim: true },
    spiffeId: { type: String, required: true },
    parent: { type: Schema.Types.ObjectId, ref: 'AgentIdentity' },
    toolScope: { type: [String], required: true, default: [] },
    createdBy: { type: String, required: true },
    active: { type: Boolean, required: true, default: true },
  },
  { collection: 'agent_identities', timestamps: true },
);

agentIdentitySchema.index({ spiffeId: 1 }, { unique: true, name: 'agent_identities_spiffe_id_unique' });
agentIdentitySchema.index({ parent: 1, active: 1 }, { name: 'agent_identities_parent_active' });

export type AgentIdentity = InferSchemaType<typeof agentIdentitySchema>;
export const AgentIdentityModel = models.AgentIdentity || model<AgentIdentity>('AgentIdentity', agentIdentitySchema);
