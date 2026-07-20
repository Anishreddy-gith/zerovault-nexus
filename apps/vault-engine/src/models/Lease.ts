import { InferSchemaType, model, models, Schema } from 'mongoose';

const leaseSchema = new Schema(
  {
    leaseId: { type: String, required: true },
    secret: { type: Schema.Types.ObjectId, ref: 'Secret', required: true },
    subject: { type: String, required: true },
    operation: { type: String, enum: ['read'], required: true },
    permissions: { type: [String], required: true, default: [] },
    taskId: { type: String },
    status: { type: String, enum: ['active', 'revoked', 'expired', 'completed'], required: true, default: 'active' },
    issuedAt: { type: Date, required: true, default: Date.now },
    expiresAt: { type: Date, required: true },
    revokedAt: { type: Date },
  },
  { collection: 'leases', timestamps: true },
);

leaseSchema.index({ leaseId: 1 }, { unique: true, name: 'leases_lease_id_unique' });
leaseSchema.index({ expiresAt: 1 }, { name: 'leases_expiry' });
leaseSchema.index({ subject: 1, expiresAt: 1 }, { name: 'leases_subject_expiry' });

export type Lease = InferSchemaType<typeof leaseSchema>;
export const LeaseModel = models.Lease || model<Lease>('Lease', leaseSchema);
