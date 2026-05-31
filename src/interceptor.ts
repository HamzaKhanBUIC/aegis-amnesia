import { AmnesiaVault } from './vault';
import crypto from 'crypto';

/**
 * Acts as middleware for Agent architectures (like LangChain, AutoGen).
 * Intercepts sensitive prompts or memory states, offloads them to the Vault,
 * and passes a safe reference pointer to the LLM.
 */
export class AgentInterceptor {
  private vault: AmnesiaVault;

  constructor() {
    this.vault = new AmnesiaVault();
  }

  /**
   * Secures sensitive context into the Vault and returns an opaque pointer.
   * @param context Sensitive context
   * @param ttlMs Time before it is completely forgotten
   */
  public secureContext(context: string, ttlMs: number = 5000): string {
    const label = `amnesia_ref_${crypto.randomBytes(4).toString('hex')}`;
    const id = this.vault.store(label, context, ttlMs);
    return id;
  }

  /**
   * Attempts to retrieve context using the pointer before sending to LLM.
   */
  public resolveContext(pointerId: string): string | null {
    return this.vault.retrieve(pointerId);
  }

  /**
   * Force drop a context early.
   */
  public forceForget(pointerId: string): void {
    this.vault.shred(pointerId);
  }
}
