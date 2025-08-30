export const PORT: number = parseInt(process.env["PORT"] || "3000", 10);
const isProd = process.env["NODE_ENV"] === "production";

export const JWT_CONFIG = {
  expiresIn: "365d",
  secret: process.env["JWT_SECRET"] || "secret",
};

export const CORS_CONFIG = {
  enabled: process.env["CORS_ENABLED"] === "true" || isProd,
  origin: process.env["CORS_ORIGIN"] || "*",
};

export const IP_HEADER_NAME = "ar-real-ip";
