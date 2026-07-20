import { HydratedDocument, InferSchemaType, model, models, Schema } from 'mongoose';

const webAuthnCredentialSchema = new Schema(
  {
    credentialId: { type: String, required: true },
    publicKey: { type: String, required: true },
    counter: { type: Number, required: true, min: 0 },
    transports: { type: [String], default: [] },
  },
  { _id: false },
);

const userSchema = new Schema(
  {
    email: { type: String, required: true, lowercase: true, trim: true },
    displayName: { type: String, required: true, trim: true },
    githubId: { type: String, sparse: true },
    roles: [{ type: Schema.Types.ObjectId, ref: 'Role', required: true }],
    webAuthnCredentials: { type: [webAuthnCredentialSchema], default: [] },
    status: { type: String, enum: ['active', 'disabled'], default: 'active', required: true },
    lastAuthenticatedAt: { type: Date },
  },
  { collection: 'users', timestamps: true },
);

userSchema.index({ email: 1 }, { unique: true, name: 'users_email_unique' });
userSchema.index(
  { githubId: 1 },
  { unique: true, sparse: true, name: 'users_github_id_unique' },
);
userSchema.index(
  { 'webAuthnCredentials.credentialId': 1 },
  { unique: true, sparse: true, name: 'users_webauthn_credential_unique' },
);

export type User = InferSchemaType<typeof userSchema>;
export type UserDocument = HydratedDocument<User>;
export const UserModel = models.User || model<User>('User', userSchema);
