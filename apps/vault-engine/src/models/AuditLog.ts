import { InferSchemaType, model, models, Schema } from 'mongoose';

const auditLogSchema = new Schema(
  {
    eventType: { type: String, required: true },
    actor: { type: String, required: true },
    action: { type: String, required: true },
    resource: { type: String, required: true },
    traceId: { type: String, required: true },
    payloadHash: { type: String, required: true },
    previousHash: { type: String, required: true },
    entryHash: { type: String, required: true },
    occurredAt: { type: Date, required: true, default: Date.now },
  },
  { collection: 'audit_logs', timestamps: false },
);

auditLogSchema.index({ occurredAt: -1 }, { name: 'audit_logs_occurred_at_desc' });
auditLogSchema.index({ actor: 1, occurredAt: -1 }, { name: 'audit_logs_actor_occurred_at' });
auditLogSchema.index({ resource: 1, occurredAt: -1 }, { name: 'audit_logs_resource_occurred_at' });

export type AuditLog = InferSchemaType<typeof auditLogSchema>;
export const AuditLogModel = models.AuditLog || model<AuditLog>('AuditLog', auditLogSchema);
