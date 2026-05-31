import { AmnesiaVault, VaultRecordPublic, AuditEvent } from './vault';
import { ShredAttestation } from './crypto';

export { AmnesiaVault, AmnesiaCrypto } from './vault';
export type { VaultRecordPublic, AuditEvent } from './vault';
export type { ShredAttestation, EncryptedPayload } from './crypto';

// Re-export the singleton vault for SDK use
export const vault = new AmnesiaVault();
