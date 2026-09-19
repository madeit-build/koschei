import { encodeEnvelope, padPlaintext, slotAad, type Slot } from './envelope.ts';
import { hpkeSeal } from './hpke.ts';

export interface SealParams {
  value: string;
  kid: string;
  recipientPublicKey: CryptoKey;
  slot: Slot;
}

export async function sealValue(params: SealParams): Promise<string> {
  const { enc, ct } = await hpkeSeal(params.recipientPublicKey, padPlaintext(params.value), slotAad(params.slot));
  return encodeEnvelope({ kid: params.kid, enc, ct });
}
