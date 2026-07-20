import { InferSchemaType, model, models, Schema } from 'mongoose';

const anomalyScoreSchema = new Schema(
  {
    subject: { type: String, required: true },
    eventId: { type: String, required: true },
    score: { type: Number, required: true, min: 0, max: 1 },
    modelVersion: { type: String, required: true },
    explanation: { type: String, required: true },
    scoredAt: { type: Date, required: true, default: Date.now },
  },
  { collection: 'anomaly_scores', timestamps: false },
);

anomalyScoreSchema.index(
  { eventId: 1, modelVersion: 1 },
  { unique: true, name: 'anomaly_scores_event_model_unique' },
);
anomalyScoreSchema.index({ subject: 1, scoredAt: -1 }, { name: 'anomaly_scores_subject_scored_at' });

export type AnomalyScore = InferSchemaType<typeof anomalyScoreSchema>;
export const AnomalyScoreModel = models.AnomalyScore || model<AnomalyScore>('AnomalyScore', anomalyScoreSchema);
