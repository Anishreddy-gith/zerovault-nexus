import { InferSchemaType, model, models, Schema } from 'mongoose';

const roleSchema = new Schema(
  {
    name: { type: String, required: true, trim: true },
    description: { type: String, required: true, trim: true },
    permissions: { type: [String], required: true, default: [] },
    system: { type: Boolean, required: true, default: false },
  },
  { collection: 'roles', timestamps: true },
);

roleSchema.index({ name: 1 }, { unique: true, name: 'roles_name_unique' });

export type Role = InferSchemaType<typeof roleSchema>;
export const RoleModel = models.Role || model<Role>('Role', roleSchema);
