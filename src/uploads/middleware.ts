import multer from "multer";

export function createUploadMiddleware(fieldName: string, maxBytes: number) {
  return multer({
    limits: {
      files: 1,
      fileSize: maxBytes,
    },
    storage: multer.memoryStorage(),
  }).single(fieldName);
}
