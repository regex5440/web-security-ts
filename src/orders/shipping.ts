import {
  decryptWithKeyring,
  deserializeEncryptedPayload,
  encryptWithKeyring,
  serializeEncryptedPayload,
  type Keyring,
} from "../storage/keyring.ts";

export type ShippingDetails = {
  name: string;
  address: string;
  city: string;
  region: string;
  postalCode: string;
};

export function encryptShippingDetails(
  details: ShippingDetails,
  _keyring: Keyring | undefined,
): string {
  return serializeEncryptedPayload(
    encryptWithKeyring(Buffer.from(JSON.stringify(details)), _keyring),
  ).toString();
}

export function decryptShippingDetails(
  serialized: string,
  _keyring: Keyring | undefined,
): ShippingDetails {
  let details: unknown;
  try {
    details = JSON.parse(
      decryptWithKeyring(
        deserializeEncryptedPayload(Buffer.from(serialized)),
        _keyring,
      ).toString(),
    );
  } catch {
    throw new Error("Invalid shipping details");
  }

  if (!isShippingDetails(details)) {
    throw new Error("Invalid shipping details");
  }

  return details;
}

function isShippingDetails(details: unknown): details is ShippingDetails {
  if (!details || typeof details !== "object") {
    return false;
  }

  const candidate = details as Record<string, unknown>;
  return (
    typeof candidate.name === "string" &&
    typeof candidate.address === "string" &&
    typeof candidate.city === "string" &&
    typeof candidate.region === "string" &&
    typeof candidate.postalCode === "string"
  );
}
