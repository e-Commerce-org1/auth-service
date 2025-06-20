import { Inject, Injectable } from '@nestjs/common';
import Redis from 'ioredis';
@Injectable()
export class RedisService {
  constructor(@Inject('REDIS_CLIENT') private readonly client: Redis) {}
  // Method to generate Redis keys for access tokens
  private buildKey(keyParts: string[]): string {
    return keyParts.join(':');
  }
  // Method to store access token in Redis with a TTL
  async storeAccessToken(
    accessToken: string,
    keyParts: string[],
    ttl: number,
  ): Promise<void> {
    const key = this.buildKey(keyParts);
    //console.log('Redis key:',key);
    await this.client.set(key, accessToken, 'EX', ttl);
  }
  // Method to retrieve access token from Redis
  async getAccessToken(keyParts: string[]): Promise<string | null> {
    const key = this.buildKey(keyParts);
    return await this.client.get(key);
  }
  // Method to validate access token against the stored token in Redis
  async validateAccessToken(
    keyParts: string[],
    accessToken: string,
  ): Promise<boolean> {
    const key = this.buildKey(keyParts);
    const storedToken = await this.client.get(key);
    return storedToken === accessToken;
  }
  // Method to delete access token from Redis
  async deleteAccessToken(keyParts: string[]): Promise<void> {
    const key = this.buildKey(keyParts);
    await this.client.del(key);
  }
}
