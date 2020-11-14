import * as BLS from '@chainsafe/bls';
import { BaseKeyPair } from './baseKeyPair';
import { AddressFormat } from './enum';
import { NotImplementedError } from './errors';
import { PrivateKey } from './iface';

/**
 * Base class for BLS keypairs.
 */
export abstract class BlsKeyPair implements BaseKeyPair {
  protected keyPair: BLS.Keypair;

  /**
   * Public constructor. By default, creates a key pair with a random master seed.
   *
   */
  protected constructor() {
    this.keyPair = BLS.generateKeyPair();
  }

  /**
   * Build a keyPair from private key.
   *
   * @param {string} prv a hexadecimal private key
   */
  recordKeysFromPrivateKey(prv: string) {
    if (BlsKeyPair.isValidBLSPrv(prv)) {
      const privateKey = BLS.PrivateKey.fromHexString(prv);
      this.keyPair = new BLS.Keypair(privateKey);
    } else {
      throw new Error('Invalid private key');
    }
  }

  /**
   * Build a keyPair from private key.
   *
   * @param {Buffer} prv a UInt8Array private key
   */
  recordKeysFromPrivateKeyBytes(prv: Buffer) {
    if (BlsKeyPair.isValidBLSPrvBytes(prv)) {
      const privateKey = BLS.PrivateKey.fromBytes(prv);
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
  public static isValidBLSPrv(prv: string): boolean {
    try {
      BLS.PrivateKey.fromHexString(prv);
      return true;
    } catch (e) {
      return false;
    }
  }

  /**
   * Whether the input is a valid BLS private key
   *
   * @param {string} prv A hexadecimal public key to validate
   * @returns {boolean} Whether the input is a valid private key or not
   */
  public static isValidBLSPrvBytes(prv: Buffer): boolean {
    try {
      BLS.PrivateKey.fromBytes(prv);
      return true;
    } catch (e) {
      return false;
    }
  }

  /**
   * Return boolean indicating whether input is valid public key for the coin.
   *
   * @param {string} pub the pub to be checked
   * @returns {boolean} is it valid?
   */
  public static isValidBLSPub(pub: string): boolean {
    try {
      BLS.PublicKey.fromHex(pub);
      return true;
    } catch (e) {
      return false;
    }
  }
}
