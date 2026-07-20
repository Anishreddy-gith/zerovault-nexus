import { InferSchemaType, model, models, Schema } from 'mongoose';

const secretSchema = new Schema(
  {
    path: { type: String, required: true, trim: true },
    name: { type: String, required: true, trim: true },
    namespace: { type: String, required: true, trim: true },
    type: { type: String, required: true, trim: true },
    status: { type: String, enum: ['active', 'revoked'], required: true, default: 'active' },
    ciphertext: { type: String, required: true },
    iv: { type: String, required: true },
    authTag: { type: String, required: true },
    wrappedDek: { type: String, required: true },
    kekKeyId: { type: String, required: true },
    version: { type: Number, required: true, min: 1, default: 1 },
    metadata: { type: Map, of: String, default: {} },
    createdBy: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  },
  { collection: 'secrets', timestamps: true },
);

secretSchema.index({ path: 1 }, { unique: true, name: 'secrets_path_unique' });
secretSchema.index({ namespace: 1, name: 1 }, { unique: true, name: 'secrets_namespace_name_unique' });
secretSchema.index({ createdBy: 1, updatedAt: -1 }, { name: 'secrets_creator_updated_at' });

export type Secret = InferSchemaType<typeof secretSchema>;
export const SecretModel = models.Secret || model<Secret>('Secret', secretSchema);
