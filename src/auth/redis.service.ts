import { Injectable } from '@nestjs/common';
import Redis from 'ioredis';
import {REDIS_CONFIG } from '../common/constants'

@Injectable()
export class RedisService {
  private client: Redis;

  constructor() {
    this.client = new Redis(REDIS_CONFIG.URL);
  }

  async storeAccessToken(userId: string, deviceId: string, accessToken: string) {
    const key = `auth:${userId}:${deviceId}`;
    await this.client.set(key, accessToken); 
  }

  async getAccessToken(userId: string, deviceId: string) {
    const key = `auth:${userId}:${deviceId}`;
    console.log("key",key);
    return this.client.get(key);
  }

  async validateAccessToken(userId: string, deviceId: string, accessToken: string) {
    const key = `auth:${userId}:${deviceId}`;
    const storedToken = await this.client.get(key);
    return storedToken ;
  }

  async deleteAccessToken(userId: string, deviceId: string) {
    const key = `auth:${userId}:${deviceId}`;
    await this.client.del(key);
  }
}