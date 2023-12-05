import {
  EncryptedData,
  Errors,
  HWWalletAdd,
  HWwalletType,
  KeyPair,
  KeyPairAdd,
  KeyRecordAdd,
  ScrambleAccount,
  SignerInterface,
  SignerType,
  SignOptions,
  WalletType,
} from "@scramble/types";
import Storage from "@scramble/storage";
import { entropyToMnemonic, generateMnemonic, mnemonicToEntropy } from "bip39";
import { decrypt, encrypt } from "@scramble/utils";
import PolkadotSigner from "@scramble/signer-polkadot";
import EthereumSigner from "@scramble/signer-ethereum";
import TronSigner from "@scramble/signer-tron";
import BitcoinSigner from "@scramble/signer-bitcoin";
import assert from "assert";
import { randomBytes } from "crypto";
import { pathParser } from "./utils";
import configs from "./configs";

class KeyRing {
  #storage: Storage;

  #isLocked: boolean;

  #signers: { [key in SignerType]: SignerInterface };

  /** @dev Generated on unlockMnemonic/getPrivateKeys to have mnemonic not stored in cleartext in memory (M02 Hacken audit) */
  #randomMnemonicSessionKey: Buffer;

  #randomPrivateKeySessionKey: Buffer;

  /** @dev Encrypted at runtime with temporary session data until wallet reset. */
  #obfuscatedMnemonic: EncryptedData;

  #obfuscatedPrivkeys: EncryptedData;

  #autoLock: ReturnType<typeof setTimeout>;

  readonly autoLockTime: number;

  constructor(storage: Storage, locktime = 60 * 60 * 1000) {
    this.#storage = storage;
    this.#isLocked = true;
    this.autoLockTime = locktime;
    this.#obfuscatedMnemonic = null;
    this.#obfuscatedPrivkeys = null;
    this.#randomMnemonicSessionKey = null;
    this.#randomPrivateKeySessionKey = null;
    this.#signers = {
      [SignerType.secp256k1]: new EthereumSigner(),
      [SignerType.ecdsa]: new PolkadotSigner(SignerType.ecdsa),
      [SignerType.ed25519]: new PolkadotSigner(SignerType.ed25519),
      [SignerType.sr25519]: new PolkadotSigner(SignerType.sr25519),
      [SignerType.secp256k1btc]: new BitcoinSigner(),
      [SignerType.secp256k1tron]: new TronSigner(),
    };
  }

  // eslint-disable-next-line class-methods-use-this
  async #generateRandomSessionKey(): Promise<Buffer> {
    return randomBytes(48);
  }

  async init(
    password: string,
    {
      strength = configs.MNEMONIC_STRENGTH,
      mnemonic = generateMnemonic(strength),
      wordList,
    }: { strength?: number; mnemonic?: string, wordList?: string[] } = {}
  ): Promise<void> {
    assert(
      !(await this.#storage.get(configs.STORAGE_KEYS.ENCRYPTED_MNEMONIC)),
      Errors.KeyringErrors.MnemonicExists
    );
    assert(password, Errors.KeyringErrors.NoPassword);
    const entropy = mnemonicToEntropy(mnemonic, wordList);
    const encrypted = await encrypt(entropy, password);
    await this.#storage.set(configs.STORAGE_KEYS.ENCRYPTED_MNEMONIC, encrypted);
  }

  async isInitialized(): Promise<boolean> {
    return !!(await this.#storage.get(configs.STORAGE_KEYS.ENCRYPTED_MNEMONIC));
  }

  #resetTimeout(): void {
    clearTimeout(this.#autoLock);
    this.#autoLock = setTimeout(() => {
      this.#obfuscatedMnemonic = null;
      this.#obfuscatedPrivkeys = null;
      this.#randomMnemonicSessionKey = null;
      this.#randomPrivateKeySessionKey = null;
      this.#isLocked = true;
    }, this.autoLockTime);
  }

  async #getPathIndex(basePath: string): Promise<number> {
    const pathIndexes =
      (await this.#storage.get(configs.STORAGE_KEYS.PATH_INDEXES)) || {};
    if (pathIndexes[basePath] === undefined) return 0;
    return pathIndexes[basePath] + 1;
  }

  async #unobfuscateMnemonic(decryptedEntropy: EncryptedData): Promise<string> {
    return entropyToMnemonic(
      await decrypt(
        decryptedEntropy,
        this.#randomMnemonicSessionKey.toString("utf-8")
      )
    );
  }

  async #unobfuscatePrivateKeys(
    decryptedEntropy: EncryptedData
  ): Promise<Record<string, string>> {
    if (!decryptedEntropy) return {};
    return JSON.parse(
      await decrypt(
        decryptedEntropy,
        this.#randomPrivateKeySessionKey.toString("utf-8")
      )
    );
  }

  async #getObfuscatedMnemonic(password: string): Promise<EncryptedData> {
    const encrypted = await this.#storage.get(
      configs.STORAGE_KEYS.ENCRYPTED_MNEMONIC
    );
    assert(encrypted, Errors.KeyringErrors.NotInitialized);
    this.#randomMnemonicSessionKey = await this.#generateRandomSessionKey();
    return encrypt(
      await decrypt(encrypted, password),
      this.#randomMnemonicSessionKey.toString("utf-8")
    );
  }

  async unlockMnemonic(password: string): Promise<void> {
    await Promise.all([
      this.#getObfuscatedMnemonic(password),
      this.#getPrivateKeys(password),
    ]).then(async (results) => {
      let rawPks: Record<string, string>;
      [this.#obfuscatedMnemonic, rawPks] = results;
      this.#obfuscatedPrivkeys = await this.#obfuscatePrivateKeys(rawPks);
      this.#isLocked = false;
      if (this.autoLockTime !== 0) {
        this.#resetTimeout();
      }
    });
  }

  async getMnemonic(password: string): Promise<string> {
    return this.#unobfuscateMnemonic(
      await this.#getObfuscatedMnemonic(password)
    );
  }

  async getPrivateKey(password: string, account: ScrambleAccount) {
    await this.unlockMnemonic(password);
    switch (account.walletType) {
      case WalletType.privkey: {
        const rawPks = await this.#unobfuscatePrivateKeys(
          this.#obfuscatedPrivkeys
        );
        if (account.pathIndex in rawPks) {
          return rawPks[account.pathIndex];
        }
        return Promise.resolve("Invalid pathIndex");
      }
      case WalletType.mnemonic: {
        const res = await this.#signers[account.signerType].generate(
          await this.#unobfuscateMnemonic(this.#obfuscatedMnemonic),
          pathParser(account.basePath, account.pathIndex, account.signerType)
        );
        return res.privateKey;
      }
      default: {
        return Promise.resolve("Wallet type not supported");
      }
    }
  }

  async createKey(key: KeyRecordAdd): Promise<ScrambleAccount> {
    assert(!this.#isLocked, Errors.KeyringErrors.Locked);
    this.#resetTimeout();
    const nextIndex = await this.#getPathIndex(key.basePath);
    let keypair: KeyPair;
    if (key.walletType === WalletType.privkey) {
      keypair = {
        privateKey: "", // we will manually set these
        publicKey: "",
        address: "",
      };
    } else {
      keypair = await this.#signers[key.signerType].generate(
        await this.#unobfuscateMnemonic(this.#obfuscatedMnemonic),
        pathParser(key.basePath, nextIndex, key.signerType)
      );
    }
    return {
      address: keypair.address,
      basePath: key.basePath,
      name: key.name,
      pathIndex: nextIndex,
      publicKey: keypair.publicKey,
      signerType: key.signerType,
      walletType: key.walletType,
      isHardware: false,
    };
  }

  async createAndSaveKey(key: KeyRecordAdd): Promise<ScrambleAccount> {
    const keyRecord = await this.createKey(key);
    await this.#saveKeyRecord(keyRecord);
    return keyRecord;
  }

  async #saveKeyRecord(keyRecord: ScrambleAccount): Promise<void> {
    const existingKeys = await this.getKeysObject();
    assert(
      !existingKeys[keyRecord.address],
      Errors.KeyringErrors.AddressExists
    );
    existingKeys[keyRecord.address] = keyRecord;
    await this.#storage.set(configs.STORAGE_KEYS.KEY_INFO, existingKeys);
    const pathIndexes =
      (await this.#storage.get(configs.STORAGE_KEYS.PATH_INDEXES)) || {};
    pathIndexes[keyRecord.basePath] = keyRecord.pathIndex;
    await this.#storage.set(configs.STORAGE_KEYS.PATH_INDEXES, pathIndexes);
  }

  async sign(msgHash: string, options: SignOptions): Promise<string> {
    assert(!this.#isLocked, Errors.KeyringErrors.Locked);
    this.#resetTimeout();
    assert(
      !Object.values(HWwalletType).includes(
        options.walletType as unknown as HWwalletType
      ),
      Errors.KeyringErrors.CannotUseKeyring
    );
    let keypair: KeyPair;
    if (options.walletType === WalletType.privkey) {
      const pubKey = (await this.getKeysArray()).find(
        (i) =>
          i.basePath === options.basePath && i.pathIndex === options.pathIndex
      ).publicKey;
      const rawPks = await this.#unobfuscatePrivateKeys(
        this.#obfuscatedPrivkeys
      );
      keypair = {
        privateKey: rawPks[options.pathIndex.toString()],
        publicKey: pubKey,
      };
    } else {
      keypair = await this.#signers[options.signerType].generate(
        await this.#unobfuscateMnemonic(this.#obfuscatedMnemonic),
        pathParser(options.basePath, options.pathIndex, options.signerType)
      );
    }
    return this.#signers[options.signerType].sign(msgHash, keypair);
  }

  async getEthereumEncryptionPublicKey(options: SignOptions): Promise<string> {
    assert(!this.#isLocked, Errors.KeyringErrors.Locked);
    this.#resetTimeout();
    assert(
      !Object.values(HWwalletType).includes(
        options.walletType as unknown as HWwalletType
      ),
      Errors.KeyringErrors.CannotUseKeyring
    );
    assert(
      options.signerType === SignerType.secp256k1,
      Errors.KeyringErrors.EnckryptDecryptNotSupported
    );
    const keypair = await this.#signers[options.signerType].generate(
      await this.#unobfuscateMnemonic(this.#obfuscatedMnemonic),
      pathParser(options.basePath, options.pathIndex, options.signerType)
    );
    return (
      this.#signers[options.signerType] as EthereumSigner
    ).getEncryptionPublicKey(keypair);
  }

  async ethereumDecrypt(
    encryptedMessage: string,
    options: SignOptions
  ): Promise<string> {
    assert(!this.#isLocked, Errors.KeyringErrors.Locked);
    this.#resetTimeout();
    assert(
      !Object.values(HWwalletType).includes(
        options.walletType as unknown as HWwalletType
      ),
      Errors.KeyringErrors.CannotUseKeyring
    );
    assert(
      options.signerType === SignerType.secp256k1,
      Errors.KeyringErrors.EnckryptDecryptNotSupported
    );
    const keypair = await this.#signers[options.signerType].generate(
      await this.#unobfuscateMnemonic(this.#obfuscatedMnemonic),
      pathParser(options.basePath, options.pathIndex, options.signerType)
    );
    return (this.#signers[options.signerType] as EthereumSigner).decrypt(
      encryptedMessage,
      keypair
    );
  }

  async getKeysObject(): Promise<{ [key: string]: ScrambleAccount }> {
    const jsonstr = await this.#storage.get(configs.STORAGE_KEYS.KEY_INFO);
    if (!jsonstr) return {};
    return jsonstr;
  }

  async getKeysArray(): Promise<ScrambleAccount[]> {
    return Object.values(await this.getKeysObject());
  }

  async addHWAccount(account: HWWalletAdd): Promise<ScrambleAccount> {
    const existingKeys = await this.getKeysObject();
    assert(!existingKeys[account.address], Errors.KeyringErrors.AddressExists);
    const hwAcc: ScrambleAccount = { isHardware: true, ...account };
    existingKeys[account.address] = hwAcc;
    await this.#storage.set(configs.STORAGE_KEYS.KEY_INFO, existingKeys);
    return hwAcc;
  }

  async renameAccount(
    address: string,
    newName: string
  ): Promise<ScrambleAccount> {
    const existingKeys = await this.getKeysObject();
    assert(existingKeys[address], Errors.KeyringErrors.AddressDoesntExists);
    const account = existingKeys[address];
    account.name = newName;
    existingKeys[address] = account;
    await this.#storage.set(configs.STORAGE_KEYS.KEY_INFO, existingKeys);
    return account;
  }

  async deleteAccount(address: string): Promise<void> {
    const existingKeys = await this.getKeysObject();
    assert(existingKeys[address], Errors.KeyringErrors.AddressDoesntExists);
    assert(
      existingKeys[address].walletType !== WalletType.mnemonic,
      Errors.KeyringErrors.CantRemoveMnemonicAddress
    );
    delete existingKeys[address];
    await this.#storage.set(configs.STORAGE_KEYS.KEY_INFO, existingKeys);
  }

  async #getPrivateKeys(
    keyringPassword: string
  ): Promise<Record<string, string>> {
    const encrypted = await this.#storage.get(
      configs.STORAGE_KEYS.ENCRYPTED_PRIVKEYS
    );
    if (!encrypted) return {};
    return JSON.parse(await decrypt(encrypted, keyringPassword)) ?? {};
  }

  async #obfuscatePrivateKeys(rawPks: Record<string, string>) {
    if (!rawPks || JSON.stringify(rawPks) === "{}") return null;
    this.#randomPrivateKeySessionKey = await this.#generateRandomSessionKey();
    return encrypt(
      rawPks.toString(),
      this.#randomPrivateKeySessionKey.toString("utf-8")
    );
  }

  async #setPrivateKey(
    pathIndex: string,
    privKey: string,
    keyringPassword: string
  ): Promise<void> {
    const allKeys = await this.#getPrivateKeys(keyringPassword);
    assert(!allKeys[pathIndex], Errors.KeyringErrors.AddressExists);
    allKeys[pathIndex] = privKey;
    const decrypted = JSON.stringify(allKeys);
    const encrypted = await encrypt(decrypted, keyringPassword);
    await this.#storage.set(configs.STORAGE_KEYS.ENCRYPTED_PRIVKEYS, encrypted);
    this.#randomPrivateKeySessionKey = await this.#generateRandomSessionKey();
    this.#obfuscatedPrivkeys = await encrypt(
      decrypted,
      this.#randomPrivateKeySessionKey.toString("utf-8")
    );
  }

  async addKeyPair(
    keyPair: KeyPairAdd,
    keyringPassword: string
  ): Promise<ScrambleAccount> {
    const existingKeys = await this.getKeysObject();
    assert(!existingKeys[keyPair.address], Errors.KeyringErrors.AddressExists);
    const kpAcc = await this.createKey({
      basePath: configs.PRIVEY_BASE_PATH,
      name: keyPair.name,
      signerType: keyPair.signerType,
      walletType: WalletType.privkey,
    });
    kpAcc.address = keyPair.address;
    kpAcc.publicKey = keyPair.publicKey;
    await this.#setPrivateKey(
      kpAcc.pathIndex.toString(),
      keyPair.privateKey,
      keyringPassword
    );
    await this.#saveKeyRecord(kpAcc);
    return kpAcc;
  }

  async reset(): Promise<void> {
    const resetPromises = Object.values(configs.STORAGE_KEYS).map((name) =>
      this.#storage.remove(name)
    );
    await Promise.all(resetPromises);
  }

  async toggleVisibility(address: string): Promise<void> {
    const existingKeys = await this.getKeysObject();
    existingKeys[address].isHidden = !existingKeys[address].isHidden;
    await this.#storage.set(configs.STORAGE_KEYS.KEY_INFO, existingKeys);
  }

  isLocked(): boolean {
    return this.#isLocked;
  }

  lock(): void {
    clearTimeout(this.#autoLock);
    this.#obfuscatedMnemonic = null;
    this.#obfuscatedPrivkeys = null;
    this.#randomPrivateKeySessionKey = null;
    this.#randomMnemonicSessionKey = null;
    this.#isLocked = true;
  }
}

export default KeyRing;
