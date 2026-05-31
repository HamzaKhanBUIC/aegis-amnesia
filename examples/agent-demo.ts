import { AgentInterceptor } from '../src/interceptor';

async function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function runDemo() {
  console.log("=========================================================");
  console.log("🧠 EPHEMERAL SELF-DESTRUCTING AGENT MEMORY POC");
  console.log("=========================================================\n");

  const interceptor = new AgentInterceptor();

  // 1. Agent receives highly sensitive context (e.g., a user's API key and social security number)
  const sensitiveContext = "USER_SSN: 000-00-0000, API_KEY: ak_live_xyz123987";
  console.log("[AGENT] Received highly sensitive payload.");
  
  // 2. We secure it in the Ephemeral Vault. It will self-destruct in 3 seconds.
  const ttl = 3000;
  console.log(`[AGENT] Securing context with Cryptographic Amnesia (TTL: ${ttl}ms)...`);
  const pointer = interceptor.secureContext(sensitiveContext, ttl);
  console.log(`[AGENT] Context secured. Opaque Pointer: ${pointer}\n`);

  // 3. Agent attempts to use it immediately
  console.log("[AGENT] Attempting to access memory (T=0s)...");
  const retrieved1 = interceptor.resolveContext(pointer);
  if (retrieved1) {
    console.log(`[AGENT] ✅ Success! Memory accessed: ${retrieved1}\n`);
  } else {
    console.log(`[AGENT] ❌ Failed to access memory.\n`);
  }

  // 4. Wait for the TTL to expire and the key to shred
  console.log(`[AGENT] Waiting for time-to-live (${ttl}ms) to expire...`);
  await sleep(ttl + 500);

  // 5. Agent attempts to access it again
  console.log("\n[AGENT] Attempting to access memory post-shredding (T=3.5s)...");
  const retrieved2 = interceptor.resolveContext(pointer);
  
  if (retrieved2) {
    console.log(`[AGENT] ❌ CRITICAL FAILURE: Memory was still accessible: ${retrieved2}`);
  } else {
    console.log(`[AGENT] ✅ SUCCESS! Cryptographic Amnesia achieved. Memory is irretrievable.`);
  }

  console.log("\n=========================================================");
  console.log("🏁 DEMONSTRATION COMPLETE");
  console.log("=========================================================");
}

runDemo();
