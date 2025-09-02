import crypto from "node:crypto";
import { VAULT_SECRET } from "src/config/app.config";

const ALGORITHM = "aes-256-cbc";
const IV = crypto.randomBytes(16); // 16 bytes for AES block size

/**
 * Encrypt plain text
 */
export function encryptText<T>(text?: T): T {
  if (!text) {
    return undefined as T;
  }

  const cipher = crypto.createCipheriv(ALGORITHM, VAULT_SECRET, IV);
  let encrypted = cipher.update(JSON.stringify(text), "utf8", "hex");
  encrypted += cipher.final("hex");
  // Store both IV and encrypted data (IV is required for decryption)
  const result = `${IV.toString("hex")}:${encrypted}`;
  return result as T;
}

/**
 * Decrypt encrypted text
 */
export function decryptText<T>(encryptedText?: unknown): T {
  if (!encryptedText) {
    return undefined as T;
  }

  if (typeof encryptedText !== "string") {
    throw new Error("Invalid encrypted text");
  }

  const [ivHex, encrypted] = encryptedText.split(":");

  if (!ivHex || !encrypted) {
    throw new Error("Invalid encrypted text");
  }

  const iv = Buffer.from(ivHex, "hex");
  const decipher = crypto.createDecipheriv(ALGORITHM, VAULT_SECRET, iv);
  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return JSON.parse(decrypted);
}
