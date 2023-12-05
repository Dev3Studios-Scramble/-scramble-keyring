import { expect } from "chai";
import { MemoryStorage, ScrambleAccountBuilder } from "@scramble/utils";
import Storage from "@scramble/storage";
import { NetworkNames } from "@scramble/types";
import KeyRing from "../src";

describe("basic test cases for keyring", () => {
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

  it("should verify storage mnemonic was intialized", async () => {
    expect(await keyring.isInitialized()).to.equals(true);
  });

  it("should verify storage mnemonic was not initialized", async () => {
    const storage2 = new Storage("keyring", { storage: new MemoryStorage() });
    const keyring2 = new KeyRing(storage2, 30000);
    expect(await keyring2.isInitialized()).to.equals(false);
  });
  it("should add a hardware wallet account ", async () => {
    const account = new ScrambleAccountBuilder()
      .reset()
      .with("isHardware", true)
      .build();
    const res = await keyring.addHWAccount({
      ...account,
      HWOptions: {
        networkName: NetworkNames.Ethereum,
        pathTemplate: "",
      },
    });
    expect(res.isHardware).to.equals(true);
  });
  it("should reset the storage", async () => {
    await keyring.reset();
    expect(await keyring.getKeysObject()).to.deep.equal({});
  });
});
