import { AmnesiaVault, VaultRecordPublic, AuditEvent } from './vault';
import { ShredAttestation } from './crypto';

export { AmnesiaVault } from './vault';
export { AmnesiaCrypto } from './crypto';
export type { VaultRecordPublic, AuditEvent } from './vault';
export type { ShredAttestation, EncryptedPayload } from './crypto';

// Re-export the singleton vault for SDK use
export const vault = new AmnesiaVault();
