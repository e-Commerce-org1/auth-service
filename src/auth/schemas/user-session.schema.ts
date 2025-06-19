import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ timestamps: true })
export class Session extends Document {
  @Prop({ required: true, index: true })
  entityId: string;

  @Prop({ required: true })
  deviceId: string;

  @Prop({ required: true })
  email: string;

  @Prop({ required: true, enum: ['user', 'admin'] })
  role: string;

  @Prop({ required: true })
  refreshToken: string;

  @Prop({ default: true })
  active: boolean;
}

export const SessionSchema = SchemaFactory.createForClass(Session);
