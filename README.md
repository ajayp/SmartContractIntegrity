## Overview
This project is all about **securing contracts and agreements** using Merkle trees. Instead of manually comparing documents or relying on basic checksum methods, we use **cryptographic hashing** to make verification **fast, efficient, and tamper-proof**.

By hashing individual clauses and structuring them into a **Merkle tree**, we can:
- Detect even the smallest changes in a contract.
- Store only the Merkle root instead of the full document.
- Quickly verify if two contracts are **identical or modified**.

---

## Why This Matters
Legal contracts, smart contracts, audits—pretty much any agreement that relies on **integrity**—needs a way to prove it hasn’t been changed. Merkle trees help **track modifications with precision** while keeping verification **lightweight and efficient**.

**How it Works:**  
✅ **Even minor edits completely change the Merkle root**—so unauthorized modifications are easy to spot.  
✅ **Clause-level hashing ensures trust**—if a section is changed, it affects the **whole tree**, not just that line.  
✅ **Widely used in legal agreements, smart contracts, and audits**—ensuring authenticity without revealing private details.

💡 _Example_: Changing *“Party A will pay $500”* to *“Party A will pay $550”* creates a **totally different hash**, making the modification obvious.

---

## Storage & Efficiency Benefits
Instead of storing entire contracts, we **only keep the Merkle root**—saving space while ensuring **proof of integrity**.

✅ **Blockchain Compatibility** – Perfect for smart contracts that need **immutable verification**.  
✅ **Legal Audits & Compliance** – Verify agreements **without exposing sensitive details**.  
✅ **Fast Document Checks** – No need for manual reviews—just compare Merkle roots.  

---

## Fast Verification Process
Comparing full contracts manually? Painful. Slow. Instead, we:
- Generate a **Merkle root for each contract**.
- Compare the roots—if they match, the contracts are identical.
- If the roots **don’t** match, we analyze **which clauses were changed**.

🔑 **Merkle Proofs** let us verify individual clauses without exposing the full contract, making it easy to prove authenticity while maintaining privacy.

---

## Features
- **Cryptographic Contract Verification** – Secure and efficient hashing using Merkle trees.
- **Clause-Level Change Detection** – Pinpoint **exact modifications** between contract versions.
- **Merkle Proof Generation** – Validate **individual clauses** with cryptographic certainty.
- **Lightweight Storage** – Keep only **Merkle roots** instead of full documents.
- **Fast Auditing & Logging** – Easily track contract history for compliance.
- **Blockchain & Legal Compatibility** – Works seamlessly for smart contracts and agreement tracking.  

## How It Works
### **Step-by-Step Breakdown**
1️⃣ **Split the contract into individual clauses** → Each clause is **hashed separately**.  
2️⃣ **Build a Merkle Tree** → Hashes are combined **layer by layer** until a **single root hash** remains.  
3️⃣ **Any clause change alters the root** → Since **higher nodes depend on lower hashes**, modifications impact **the entire structure**.  
4️⃣ **Compare Merkle roots** → Matching roots mean contracts are identical; if different, changes occurred.  
5️⃣ **Clause-Level Comparison** → Identifies which **specific clauses** differ.  
6️⃣ **Merkle Proofs** → Allows verification of **individual clauses** without exposing the full contract.  

**EXAMPLE 1:**  
> <img alt="Example 1 Screenshot" width="725" alt="image" src="https://github.com/user-attachments/assets/4ec71e8e-8749-4c1c-9e02-f90130cbfd73" width="400px"  />


**EXAMPLE 2:**  
> <img alt="Example 2 Screenshot with duplicate hash" src="https://github.com/user-attachments/assets/28cd7623-fd0e-41a8-a35c-aadef687d38a" width="400px" />

---

## Installation

1. **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd <repository_name>
    ```

 2. **Create a Python virtual environment (recommended):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: .\venv\Scripts\activate
    ```

3. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```
   
4. Run the demo:
   ```sh
   streamlit run app.py
   ```

 5. Browse to http://localhost:8501  

---

---
