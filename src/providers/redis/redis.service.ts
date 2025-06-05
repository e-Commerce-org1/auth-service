
import { Inject, Injectable } from '@nestjs/common';
import Redis from 'ioredis';
import { WINSTON_MODULE_PROVIDER } from 'nest-winston';


@Injectable()
export class RedisService {

  constructor(
    @Inject('REDIS_CLIENT') private readonly client: Redis,
  
  ) {}

  private buildKey(keyParts: string[]): string {
    return keyParts.join(':');
  }

  async storeAccessToken(
    accessToken: string,
    keyParts: string[],
    ttl: number,
  ): Promise<void> {
    const key = this.buildKey(keyParts);
    await this.client.set(key, accessToken, 'EX', ttl);
    
  }

  async getAccessToken(keyParts: string[]): Promise<string | null> {
    const key = this.buildKey(keyParts);
    return  await this.client.get(key);

  }

  async validateAccessToken(
    keyParts: string[],
    accessToken: string,
  ): Promise<boolean> {
    const key = this.buildKey(keyParts);
    const storedToken = await this.client.get(key);
    return  storedToken === accessToken;

  }

  async deleteAccessToken(keyParts: string[]): Promise<void> {
    const key = this.buildKey(keyParts);
    await this.client.del(key);
 
  }
}
