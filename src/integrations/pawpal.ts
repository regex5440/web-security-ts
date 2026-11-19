import { createHmac, timingSafeEqual } from "node:crypto";

export function createPawPalReference(
  orderId: number,
  totalCents: number,
  pawPalApiKey: string,
): string {
  const payload = `${orderId}:${totalCents}`;
  const signature = createHmac("sha256", pawPalApiKey)
    .update(payload)
    .digest("hex")
    .slice(0, 16);
  return `pawpal_${orderId}_${signature}`;
}

export function createPawPalCheckoutUrl(orderId: number): string {
  const checkoutUrl = new URL("https://pawpal.example/checkout");
  checkoutUrl.searchParams.set("orderId", String(orderId));
  return checkoutUrl.toString();
}

export type PawPalWebhookVerification =
  | { outcome: "unauthorized" }
  | { outcome: "malformed" }
  | { outcome: "approved"; orderId: number };

export function verifyPawPalWebhook(
  providedKey: Buffer,
  expectedKey: Buffer,
  payload: unknown,
): PawPalWebhookVerification {
  try {
    if (!timingSafeEqual(providedKey, expectedKey)) {
      return { outcome: "unauthorized" };
    }
  } catch {
    return { outcome: "unauthorized" };
  }
  const payloadRecord =
    typeof payload === "object" && payload !== null
      ? (payload as Record<string, unknown>)
      : {};
  const orderId =
    typeof payloadRecord.orderId === "number"
      ? payloadRecord.orderId
      : Number.NaN;

  if (
    Number.isNaN(orderId) ||
    orderId <= 0 ||
    payloadRecord.status !== "approved"
  ) {
    return { outcome: "malformed" };
  }

  return { outcome: "approved", orderId };
}
