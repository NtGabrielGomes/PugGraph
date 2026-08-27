export {};

declare module "libsodium-wrappers" {
  export function crypto_auth_hmacsha256(message: Uint8Array, key: Uint8Array): Uint8Array;
}
