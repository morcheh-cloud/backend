export const PORT: number = parseInt(process.env["PORT"] || "3000", 10);

export const JWT_CONFIG = {
  expiresIn: "365d",
  secret: process.env["JWT_SECRET"] || "secret",
};
