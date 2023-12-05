// eslint-disable-next-line import/no-extraneous-dependencies
import { expect } from "chai";
import { MemoryStorage } from "@scramble/utils";
import Storage from "@scramble/storage";
import KeyRing from "../src";

describe("Keyring locking tests", () => {
  const memStorage = new MemoryStorage();
  const storage = new Storage("keyring", { storage: memStorage });
  const keyring = new KeyRing(storage, 2000);
  const password = "helloworld";
  // eslint-disable-next-line prefer-arrow-callback,func-names
  it("keyring should lock and unlock properly", function (done) {
    this.timeout(15000);
    keyring.init(password).then(() => {
      expect(keyring.isLocked()).to.be.equals(true);
      keyring.unlockMnemonic(password).then(() => {
        expect(keyring.isLocked()).to.be.equals(false);
        setTimeout(() => {
          expect(keyring.isLocked()).to.be.equals(true);
          keyring.lock();
          done();
        }, 2000);
      });
    });
  });
});
