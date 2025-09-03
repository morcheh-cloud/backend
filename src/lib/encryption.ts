const encryptpwd = require("encrypt-with-password");

import { VAULT_SECRET } from "src/config/app.config";

export function encryptText<T>(text?: T): T {
  if (!text) {
    return undefined as T;
  }
  const encrypted = encryptpwd.encrypt(JSON.stringify(text), VAULT_SECRET); // ---> this is the encrypted (output) value
  return encrypted as T;
}

export function decryptText<T>(encryptedText?: unknown): T {
  if (!encryptedText) {
    return undefined as T;
  }
  const decrypted = encryptpwd.decrypt(encryptedText, VAULT_SECRET); // ---> this decrypts the encrypted value and yields the original text
  return JSON.parse(decrypted);
}
