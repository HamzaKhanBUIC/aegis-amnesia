async function populate() {
  const API = 'http://localhost:3747';
  
  const items = [
    {
      label: 'stripe-live-secret-key',
      plaintext: 'sk_live_51Nz...8bH9s2kP9a1m7c',
      ttlMs: 300000 // 5 minutes (perfect for manual shredding test)
    },
    {
      label: 'openai-api-key',
      plaintext: 'sk-proj-4aB7...L9pQxYz7a2',
      ttlMs: 60000 // 60 seconds (perfect for watching the countdown)
    },
    {
      label: 'user-ssn-pii',
      plaintext: 'SSN: 999-00-1234 | DOB: 1989-10-12',
      ttlMs: 25000 // 25 seconds
    }
  ];

  console.log('Sending mock sensitive payloads to the running Amnesia Daemon...');

  for (const item of items) {
    try {
      const res = await fetch(`${API}/memory/store`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(item)
      });
      if (res.ok) {
        const data = await res.json();
        console.log(`✅ Loaded: ${item.label} (ID: ${data.id}) - TTL: ${item.ttlMs / 1000}s`);
      } else {
        console.error(`❌ Failed loading ${item.label}: ${res.statusText}`);
      }
    } catch (e: any) {
      console.error(`❌ Error connecting to server: ${e.message}`);
    }
  }

  console.log('\nAll ready! Go ahead and open http://localhost:3747 in your browser to see them live.');
}

populate();
