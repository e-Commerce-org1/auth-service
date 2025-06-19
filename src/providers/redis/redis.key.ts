export const RedisKeys = {
  accessTokenKey: (
    role: string,
    entityId: string,
    deviceId: string,
  ): string[] => ['auth', role, entityId, deviceId],
  TTL: {
    ACCESS_TOKEN: 60 * 60 * 24,
  },
};
