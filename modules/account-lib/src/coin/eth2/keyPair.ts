import { BlsKeyPair } from '../baseCoin/blsKeyPair';
import { DefaultKeys } from '../baseCoin/iface';

/**
 * Ethereum keys and address management.
 */
export class KeyPair extends BlsKeyPair {
  /**
   * Public constructor. By default, creates a key pair with a random master seed.
   *
   */
  constructor() {
    super();
  }

  /**
   * ETH2 default keys format is a pair of Uint8Array keys
   *
   * @returns { DefaultKeys } The keys in the defined format
   */
  getKeys(): DefaultKeys {
    if (this.keyPair) {
      return { prv: this.keyPair.privateKey.toHexString(), pub: this.keyPair.publicKey.toHexString() };
    }
    throw new Error('KeyPair has not been specified');
  }

  /**
   * Get an Ethereum public address
   *
   * @returns {string} The address derived from the public key
   */
  getAddress(): string {
    return this.getKeys().pub;
  }

  static isValidPub(pub: string): boolean {
    return BlsKeyPair.isValidBLSPub(pub);
  }

  static isValidPrv(prv: string | Buffer) {
    if (typeof prv === 'string') {
      return BlsKeyPair.isValidBLSPrv(prv);
    }
    return BlsKeyPair.isValidBLSPrvBytes(prv);
  }
}
