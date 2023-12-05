// eslint-disable-next-line import/no-extraneous-dependencies
import { expect } from "chai";
import {
  hexToBuffer,
  MemoryStorage,
  ScrambleAccountBuilder,
} from "@scramble/utils";
import Storage from "@scramble/storage";
import { SignerType, WalletType } from "@scramble/types";
import Wallet from "ethereumjs-wallet";
import KeyRing from "../src";

describe("Private Key Import / Export", () => {
  const KR_PWD = "helloworld";
  const accountBuilder = new ScrambleAccountBuilder();
  const keyPairs = ScrambleAccountBuilder.getTestingKeyPairs();
  let keyring: KeyRing;
  let storage;
  const USED_MNEMONIC = keyPairs[0].mnemonic;

  before(() => {
    storage = new Storage("keyring", { storage: new MemoryStorage() });
    keyring = new KeyRing(storage, 30000);
    keyring.init(KR_PWD, { mnemonic: USED_MNEMONIC, strength: 128 });
  });

  it("should export a private key if wallet type private key", async () => {
    // insert private keys from another mnemonic / wallet 1
    const expectedPrivKeyResult = keyPairs[1].pairs[0].privateKey;
    const publicAddr = keyPairs[1].pairs[0].publicKey;

    const signerType = SignerType.secp256k1;
    const account = accountBuilder
      .reset()
      .with("signerType", signerType)
      .with("walletType", WalletType.privkey)
      .with("address", publicAddr)
      .with("pathIndex", 0)
      .with("basePath", "m/44'/60'/0'/0")
      .build();

    // import private key into storage
    const buffer = hexToBuffer(expectedPrivKeyResult);
    const wallet = new Wallet(buffer);
    const newAddress = `0x${wallet.getAddress().toString("hex")}`;
    expect(newAddress).to.equals(publicAddr);
    await keyring.unlockMnemonic(KR_PWD);
    await keyring.addKeyPair(
      {
        privateKey: wallet.getPrivateKeyString(),
        publicKey: wallet.getPublicKeyString(),
        address: wallet.getAddressString(),
        name: "",
        signerType,
      },
      KR_PWD
    );

    expect(account.walletType).to.equal(WalletType.privkey);
    expect(await keyring.getPrivateKey(KR_PWD, account)).equals(
      expectedPrivKeyResult
    );
  }).timeout(10000);

  it("should return Invalid pathIndex for private key export non exist", async () => {
    storage = new Storage("keyring", { storage: new MemoryStorage() });
    keyring = new KeyRing(storage, 30000);
    await keyring.init(KR_PWD, { mnemonic: USED_MNEMONIC, strength: 128 });
    const accountInUse = accountBuilder
      .reset()
      .with("walletType", WalletType.privkey)
      .build();

    const res = await keyring.getPrivateKey(KR_PWD, accountInUse);
    expect(res).to.equals("Invalid pathIndex");
  }).timeout(5000);

  it("should return provide a default message if wallet is not supported", async () => {
    storage = new Storage("keyring", { storage: new MemoryStorage() });
    keyring = new KeyRing(storage, 30000);
    await keyring.init(KR_PWD, { mnemonic: USED_MNEMONIC, strength: 128 });
    const accountInUse = accountBuilder
      .reset()
      .with("walletType", WalletType.ledger)
      .build();
    const res = await keyring.getPrivateKey(KR_PWD, accountInUse);
    expect(res).to.equals("Wallet type not supported");
  }).timeout(5000);

  it("should return provide a default message if wallet is not supported", async () => {
    storage = new Storage("keyring", { storage: new MemoryStorage() });
    keyring = new KeyRing(storage, 30000);
    await keyring.init(KR_PWD, { mnemonic: USED_MNEMONIC, strength: 128 });
    const accountInUse = accountBuilder
      .reset()
      .with("walletType", WalletType.trezor)
      .build();
    const res = await keyring.getPrivateKey(KR_PWD, accountInUse);
    expect(res).to.equals("Wallet type not supported");
  }).timeout(5000);
});
