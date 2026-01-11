import { webcrypto } from 'crypto';
import bs58 from 'bs58';
import { Grinder, GrinderStats, FoundKey, Pattern } from './types';
import { matchesPattern } from './pattern';

const subtle = webcrypto.subtle;

export class CpuGrinder implements Grinder {
  private pattern: Pattern;
  private attempts: number = 0;
  private startTime: number = Date.now();

  constructor(pattern: Pattern) {
    this.pattern = pattern;
  }

  async searchBatch(maxAttempts: number): Promise<FoundKey | null> {
    const endAttempts = this.attempts + maxAttempts;

    while (this.attempts < endAttempts) {
      try {
        // Generate Ed25519 keypair using Web Crypto API
        const keyPair = (await subtle.generateKey(
          'Ed25519' as unknown as EcKeyGenParams,
          true, // extractable
          ['sign', 'verify']
        )) as CryptoKeyPair;

        // Export public key as raw bytes
        const publicKeyBuffer = await subtle.exportKey('raw', keyPair.publicKey);
        const publicKey = new Uint8Array(publicKeyBuffer);

        // Export private key as PKCS8 format
        const privateKeyPkcs8 = await subtle.exportKey('pkcs8', keyPair.privateKey);

        // Extract the raw 32-byte seed from PKCS8 (it's at offset 16 for Ed25519)
        const pkcs8Bytes = new Uint8Array(privateKeyPkcs8);
        const seed = pkcs8Bytes.slice(16, 48);

        // Encode public key as Base58 (Solana address)
        const address = bs58.encode(publicKey);

        this.attempts++;

        // Check pattern match
        if (matchesPattern(address, this.pattern)) {
          // Build 64-byte private key (seed + public key) for Solana compatibility
          const fullPrivateKey = new Uint8Array(64);
          fullPrivateKey.set(seed, 0);
          fullPrivateKey.set(publicKey, 32);

          return {
            publicKey,
            privateKey: fullPrivateKey,
            address,
            attempts: this.attempts,
          };
        }
      } catch {
        this.attempts++;
      }
    }

    return null;
  }

  getStats(): GrinderStats {
    const elapsedMs = Date.now() - this.startTime;
    const elapsedSec = elapsedMs / 1000;
    return {
      attempts: this.attempts,
      rate: elapsedSec > 0 ? this.attempts / elapsedSec : 0,
      elapsedMs,
    };
  }

  reset(): void {
    this.attempts = 0;
    this.startTime = Date.now();
  }
}
