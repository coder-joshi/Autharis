/** Enable each optional discovery feature only when its endpoint is implemented. */
export const features = {
  userinfo: false,
  refreshTokens: false,
  revocation: false,
  endSession: false,
} as const;
