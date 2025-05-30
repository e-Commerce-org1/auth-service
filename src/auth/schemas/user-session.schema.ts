import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ timestamps: true })
export class UserSession extends Document {
  @Prop({ required: true })
  userId: string;

  @Prop({ required: true })
  deviceId: string;

  @Prop({ required: true })
  email: string;

  @Prop({ required: true })
  role: string; // user or admin

  @Prop({ required: true })
  refreshToken: string;

  @Prop({ default: true })
  active: boolean;
}

export const UserSessionSchema = SchemaFactory.createForClass(UserSession);
