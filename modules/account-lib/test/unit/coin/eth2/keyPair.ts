import should from 'should';
import { KeyPair } from '../../../../src/coin/eth2';
import * as testData from '../../../resources/eth2/eth2';

const pub = testData.ACCOUNT_1.publicKey;
const prv = testData.ACCOUNT_1.privateKey;

describe('Eth2 Key Pair', () => {
  describe('should create a valid KeyPair', () => {
    it('from an empty value', async () => {
      const keyPair = new KeyPair();
      await keyPair.generateKeyPair();
      should.exists(keyPair.getKeys().privateKey);
      should.exists(keyPair.getKeys().publicKey);
      should.equal(
        keyPair
          .getKeys()
          .privateKey.toHexString()
          .slice(0, 2),
        '0x',
      );
      should.equal(
        keyPair
          .getKeys()
          .publicKey.toHexString()
          .slice(0, 2),
        '0x',
      );
    });

    it('without source', async () => {
      const keyPair = new KeyPair();
      await keyPair.generateKeyPair();
      should.exists(keyPair.getKeys().privateKey);
      should.exists(keyPair.getKeys().publicKey);
    });

    it('from a private key', async () => {
      const baseKeyPair = new KeyPair();
      await baseKeyPair.generateKeyPair();
      const inheritKeyPair = new KeyPair();
      await inheritKeyPair.recordKeysFromPrivateKey(baseKeyPair.getKeys().privateKey.toHexString());
      should.equal(inheritKeyPair.getKeys().privateKey.toHexString(), baseKeyPair.getKeys().privateKey.toHexString());
    });

    it('from a byte array private key', async () => {
      const privateKey = '0x' + Buffer.from(testData.ACCOUNT_1.privateKeyBytes).toString('hex');
      const keyPair = new KeyPair();
      await keyPair.recordKeysFromPrivateKey(privateKey);
      should.equal(keyPair.getKeys().privateKey.toHexString(), privateKey);
    });
  });

  describe('should fail to create a KeyPair', () => {
    it('from a public key', () => {
      should.throws(
        () => new KeyPair().recordKeysFromPublicKey(pub),
        e => e.message.includes(testData.errorMessageInvalidPublicKey),
      );
    });

    it('from an invalid private key', async () => {
      const shorterPrv = '82A34E';
      const longerPrv = prv + '1';
      await new KeyPair().recordKeysFromPrivateKey(shorterPrv).should.be.rejectedWith(Error);
      await new KeyPair().recordKeysFromPrivateKey(longerPrv).should.be.rejectedWith(Error);
      await new KeyPair().recordKeysFromPrivateKey(prv + pub).should.be.rejectedWith(Error);
    });
  });
});
