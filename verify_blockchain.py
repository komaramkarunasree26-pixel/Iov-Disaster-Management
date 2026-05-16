import json
import hashlib
import os

def verify_chain():
    ledger_path = 'uploads/emergency_ledger.json'
    
    if not os.path.exists(ledger_path):
        return "No ledger found. Please generate data first."

    with open(ledger_path, 'r') as f:
        chain = json.load(f)

    for i in range(1, len(chain)):
        prev_block = chain[i-1]
        current_block = chain[i]

        # 1. Re-calculate the hash of the previous block to see if it was modified
        recalculated_prev_hash = hashlib.sha256(
            (str(prev_block['index']) + 
             str(prev_block['timestamp']) + 
             str(prev_block['data']) + 
             str(prev_block['prev_hash'])).encode('utf-8')
        ).hexdigest()

        # 2. Check if the current block's 'prev_hash' matches the actual previous hash
        if current_block['prev_hash'] != recalculated_prev_hash:
            return f"🚨 TAMPERING DETECTED at Block {i}! Data integrity compromised."

    return "✅ Blockchain Verified: All emergency logs are authentic and untampered."

if __name__ == "__main__":
    print(verify_chain())