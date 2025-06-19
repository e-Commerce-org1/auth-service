import { Module, Global } from '@nestjs/common';
import Redis from 'ioredis';
import { REDIS_CONFIG } from '../common/constants';

@Global()
@Module({
  providers: [
    {
      provide: 'REDIS_CLIENT',
      useFactory: () => {
        const client = new Redis(REDIS_CONFIG.URL);
        console.log(`Redis connected to ${REDIS_CONFIG.URL}`);
        return client;
      },
    },
  ],
  exports: ['REDIS_CLIENT'],
})
export class RedisModule {}
