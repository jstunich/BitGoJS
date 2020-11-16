import * as BLS from '@chainsafe/bls';
import { BaseKeyPair } from './baseKeyPair';
import { AddressFormat } from './enum';
import { NotImplementedError } from './errors';

let initialized = false;
const initialize = async () => {
  await BLS.initBLS();
  initialized = true;
};

/**
 * Base class for BLS keypairs.
 */
export abstract class BlsKeyPair implements BaseKeyPair {
  protected keyPair: BLS.Keypair;

  async generateKeyPair() {
    if (!initialized) {
      await initialize();
    }
    this.keyPair = BLS.generateKeyPair();
  }

  /**
   * Build a keyPair from private key.
   *
   * @param {string} prv a hexadecimal private key
   */
  async recordKeysFromPrivateKey(prv: string) {
    if (!initialized) {
      await initialize();
    }
    if (this.isValidBLSPrv(prv)) {
      const privateKey = BLS.PrivateKey.fromHexString(prv);
      this.keyPair = new BLS.Keypair(privateKey);
    } else {
      throw new Error('Invalid private key');
    }
  }

  /**
   * Note - this is not possible using BLS. BLS does not support pubkey derived key gen
   *
   * @param {string} pub - An extended, compressed, or uncompressed public key
   */
  recordKeysFromPublicKey(pub: string): void {
    throw new NotImplementedError('Public key derivation is not supported in bls');
  }

  getAddress(format?: AddressFormat): string {
    throw new NotImplementedError('getAddress not implemented');
  }

  getKeys(): any {
    throw new NotImplementedError('getKeys not implemented');
  }

  /**
   * Whether the input is a valid BLS private key
   *
   * @param {string} prv A hexadecimal public key to validate
   * @returns {boolean} Whether the input is a valid private key or not
   */
  isValidBLSPrv(prv: string): boolean {
    try {
      BLS.PrivateKey.fromHexString(prv);
      return true;
    } catch (e) {
      return false;
    }
  }
}
