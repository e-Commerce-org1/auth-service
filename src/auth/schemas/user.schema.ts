import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';

export type UserDocument = User &
  Document & {
    _id: Types.ObjectId;
  };

@Schema({ timestamps: true })
export class User {
  @Prop({ required: true })
  name: string;

  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: true })
  password: string;

  @Prop({ default: false })
  isVerified: boolean;

  @Prop({
    type: String,
    enum: ['active', 'inactive', 'block', 'unblock'],
    default: 'inactive',
  })
  isActive: string;

  @Prop({ type: String })
  phoneNumber: string;

  @Prop({ default: 'user' })
  role: string;

  @Prop()
  deviceId: string;
  @Prop({
    type: [
      {
        street: { type: String, required: true },
        city: { type: String, required: true },
        state: { type: String, required: true },
        country: { type: String, required: true },
        postalCode: { type: String, required: true },
        isDefault: { type: Boolean, default: false },
        addressType: {
          type: String,
          enum: ['home', 'work', 'other'],
          default: 'home',
        },
      },
    ],
    default: [],
  })
  addresses: Array<{
    _id?: Types.ObjectId;
    street: string;
    city: string;
    state: string;
    country: string;
    postalCode: string;
    isDefault?: boolean;
    addressType?: 'home' | 'work' | 'other';
  }>;
}

export const UserSchema = SchemaFactory.createForClass(User);
