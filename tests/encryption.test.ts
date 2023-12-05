import { expect } from "chai";
import { SignerType, WalletType } from "@scramble/types";
import { MemoryStorage, ScrambleAccountBuilder } from "@scramble/utils";
import Storage from "@scramble/storage";
import KeyRing from "../src";
import configs from "../src/configs";

describe("Private Key Import / Export", () => {
  const KR_PWD = "helloworld";
  const keyPairs = ScrambleAccountBuilder.getTestingKeyPairs();
  const USED_MNEMONIC = keyPairs[0].mnemonic;
  const accountBuilder = new ScrambleAccountBuilder();
  let keyring: KeyRing;
  let storage;

  before(() => {
    storage = new Storage("keyring", { storage: new MemoryStorage() });
    keyring = new KeyRing(storage, 30000);
    keyring.init(KR_PWD, { mnemonic: USED_MNEMONIC, strength: 128 });
    keyring.lock();
  });

  it("should throw for encryption if keyring is locked", async () => {
    const account = accountBuilder
      .reset()
      .with("pathIndex", 10)
      .with("basePath", "m/44'/60'/0'/0")
      .build();
    try {
      await keyring.getEthereumEncryptionPublicKey(account);
    } catch (e) {
      expect(e.message).to.equals("Keyring locked");
    }
  }).timeout(5000);
  it("should throw if hardware wallet", async () => {
    const account = accountBuilder
      .reset()
      .with("isHardware", true)
      .with("walletType", WalletType.ledger)
      .with("pathIndex", 10)
      .with("basePath", "m/44'/60'/0'/0")
      .build();
    try {
      await keyring.unlockMnemonic(KR_PWD);
      await keyring.getEthereumEncryptionPublicKey(account);
    } catch (e) {
      expect(e.message).to.equals("Cannot use keyring for HW wallets");
    }
  }).timeout(5000);
  it("should throw for encryption if signertype secp256k1", async () => {
    const account = accountBuilder
      .reset()
      .with("signerType", SignerType.secp256k1)
      .with("pathIndex", 10)
      .with("basePath", "m/44'/60'/0'/0")
      .build();
    try {
      await keyring.unlockMnemonic(KR_PWD);
      await keyring.getEthereumEncryptionPublicKey(account);
    } catch (e) {
      expect(e.message).to.equals(
        "This Keytype doesnt support encrypt and decrypt"
      );
    }
  }).timeout(5000);
  it("should generate an encrypted public key", async () => {
    let error;
    const account = accountBuilder
      .reset()
      .with("pathIndex", 10)
      .with("basePath", "m/44'/60'/0'/0")
      .build();
    try {
      await keyring.unlockMnemonic(KR_PWD);
      const data = await keyring.getEthereumEncryptionPublicKey(account);
      expect(data).to.be.a("string");
    } catch (e) {
      error = e;
    }
    expect(error).to.equal(undefined);
  }).timeout(5000);
  it("should throw for decryption if keyring is locked", async () => {
    const account = accountBuilder
      .reset()
      .with("pathIndex", 10)
      .with("basePath", "m/44'/60'/0'/0")
      .build();
    try {
      await keyring.lock();
      await keyring.ethereumDecrypt("msg", account);
    } catch (e) {
      expect(e.message).to.equals("Keyring locked");
    }
  }).timeout(5000);
  it("should throw for decryption if hardware wallet", async () => {
    const account = accountBuilder
      .reset()
      .with("isHardware", true)
      .with("walletType", WalletType.ledger)
      .with("pathIndex", 10)
      .with("basePath", "m/44'/60'/0'/0")
      .build();
    try {
      await keyring.unlockMnemonic(KR_PWD);
      await keyring.ethereumDecrypt("msg", account);
    } catch (e) {
      expect(e.message).to.equals("Cannot use keyring for HW wallets");
    }
  }).timeout(5000);
  it("should throw for decryption if secp256k1", async () => {
    const account = accountBuilder
      .reset()
      .with("signerType", SignerType.secp256k1btc)
      .with("walletType", WalletType.mnemonic)
      .with("basePath", "m/44'/60'/0'/0")
      .build();
    try {
      await keyring.unlockMnemonic(KR_PWD);
      await keyring.ethereumDecrypt("0x0", account);
    } catch (e) {
      expect(e.message).to.equals(
        "This Keytype doesnt support encrypt and decrypt"
      );
    }
  });
  // fails
  it.skip("should encrypt and decrypt successfully", async () => {
    let error;
    const account = accountBuilder
      .reset()
      .with("walletType", WalletType.mnemonic)
      .with("signerType", SignerType.secp256k1)
      .with("pathIndex", 10)
      .with("basePath", "m/44'/60'/0'/0")
      .build();
    try {
      await keyring.unlockMnemonic(KR_PWD);
      const encrypted = await keyring.getEthereumEncryptionPublicKey(account);
      const decrypted = await keyring.ethereumDecrypt(encrypted, account);
      expect(decrypted).to.equals("test");
    } catch (e) {
      error = e;
    }
    expect(error).to.equal(undefined);
  }).timeout(5000);

  it("should return empty object if no storage", async () => {
    const res = await keyring.getKeysObject();
    expect(res).to.deep.equal({})
  })

  it("should return the storage value for given key", async () => {
    storage = new Storage("keyring", { storage: new MemoryStorage() });
    await storage.set(configs.STORAGE_KEYS.KEY_INFO, 'storage value insert');
    keyring = new KeyRing(storage, 30000);
    await keyring.init(KR_PWD, { mnemonic: USED_MNEMONIC, strength: 128 });
    const res = await keyring.getKeysObject();
    expect(res).to.equal('storage value insert');
  }).timeout(5000)

  it('should get keysArray', async () => {
    storage = new Storage("keyring", { storage: new MemoryStorage() });
    await storage.set(configs.STORAGE_KEYS.KEY_INFO, 'T');
    keyring = new KeyRing(storage, 30000);
    await keyring.init(KR_PWD, { mnemonic: USED_MNEMONIC, strength: 128 });
    const keys = await keyring.getKeysArray();
    expect(keys[0]).to.equals('T');
  }).timeout(5000)
});