import hashlib
from typing import List, Tuple, Literal

# --- Helpers ---
def hash_data(data: str) -> str:
    """Generate SHA-256 hash for the given string."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def build_merkle_tree(leaf_hashes: List[str]) -> List[List[str]]:
    """Builds a Merkle Tree ensuring unpaired nodes are properly hashed."""
    if not leaf_hashes:
        return [] # Handle empty input

    tree = [leaf_hashes]
    while len(tree[-1]) > 1:
        level = tree[-1]
        next_level = []

        # Process in pairs, properly hashing unpaired nodes
        for i in range(0, len(level), 2):
            left_child = level[i]
            # Handle odd number of nodes by duplicating the last one
            right_child = level[i + 1] if i + 1 < len(level) else level[i]

            # Hash the pair (left + right)
            combined = hash_data(left_child + right_child)
            next_level.append(combined)

        tree.append(next_level)
    return tree

def get_merkle_root(tree: List[List[str]]) -> str:
    """Returns the Merkle root."""
    return tree[-1][0] if tree and tree[-1] else 'EMPTY_CONTRACT' # Check if root level is not empty

def compare_merkle_roots(root1: str, root2: str) -> bool:
    """Compares two Merkle roots for equality."""
    return root1 == root2

def get_clause_comparison_report(hashes_v1: List[str], hashes_v2: List[str], clauses_v1: List[str], clauses_v2: List[str]) -> List[str]:
    """
    Compares individual clause hashes and returns a list of strings detailing differences.
    Assumes clauses_v1 corresponds to hashes_v1 and clauses_v2 to hashes_v2.
    """
    report_lines = ["🔎 Clause-Level Comparison:"]
    min_len = min(len(hashes_v1), len(hashes_v2))
    max_len = max(len(hashes_v1), len(hashes_v2))

    for i in range(min_len):
        h1 = hashes_v1[i]
        h2 = hashes_v2[i]
        if h1 == h2:
            report_lines.append(f"Clause {i+1}: ✅ Match")
        else:
            report_lines.append(f"Clause {i+1}: ❌ Difference")
            report_lines.append(f"   🔹 V1: {clauses_v1[i]}")
            report_lines.append(f"   🔹 V2: {clauses_v2[i]}")

    # Report clauses only present in the longer version
    if max_len > min_len:
        report_lines.append("\nAdditional Clauses:")
        if len(hashes_v1) > len(hashes_v2):
            report_lines.append("   🔹 V1 has additional clauses:")
            for i in range(min_len, max_len):
                report_lines.append(f"      Clause {i+1}: {clauses_v1[i]}")
        else:
            report_lines.append("   🔹 V2 has additional clauses:")
            for i in range(min_len, max_len):
                 report_lines.append(f"      Clause {i+1}: {clauses_v2[i]}")
    return report_lines

# A Merkle proof is a list of (hash, side) tuples
# side is 'left' or 'right' indicating the position of the sibling
MerkleProof = List[Tuple[str, Literal['left', 'right']]]

def get_merkle_proof(tree: List[List[str]], target_hash: str) -> MerkleProof:
    """
    Generates a Merkle proof for a specific leaf hash.
    Proof consists of sibling hashes and their side relative to the target path.
    """
    if not tree or not tree[0]: # Ensure tree and leaf level are not empty
        return []

    proof_revised: MerkleProof = []
    current_hash_up = target_hash

    for level_index in range(len(tree) - 1): # Iterate up to the level before the root
        level = tree[level_index]
        found_in_level = False
        for i in range(0, len(level), 2):
            left_node = level[i]
            # Handle odd number of nodes by duplicating the last one, matching build_merkle_tree
            right_node = level[i + 1] if i + 1 < len(level) else level[i]

            if current_hash_up == left_node:
                # Target is the left node, sibling is the right
                # Append the sibling hash and its side ('right')
                proof_revised.append((right_node, 'right'))
                # Compute the parent hash for the next iteration (left + right)
                current_hash_up = hash_data(left_node + right_node)
                found_in_level = True
                break # Move to the next level up
            elif current_hash_up == right_node:
                 # Target is the right node, sibling is the left
                 # Append the sibling hash and its side ('left')
                 proof_revised.append((left_node, 'left'))
                 # Compute the parent hash for the next iteration (still left + right order as per build)
                 current_hash_up = hash_data(left_node + right_node)
                 found_in_level = True
                 break # Move to the next level up

        if not found_in_level:
            # This means the current_hash_up was not found in the expected level.
            # This could indicate an invalid target_hash or a broken tree structure.
            # For a POC, we can return an empty proof.
            return []

    # After the loop, current_hash_up should be the root.
    # The verification function will compare this computed root with the expected root.
    return proof_revised


def verify_merkle_proof(proof: MerkleProof, target_hash: str, merkle_root: str) -> bool:
    """
    Verifies a Merkle proof against the expected root.
    Uses the side information in the proof to correctly order hashes.
    """
    computed_hash = target_hash
    for sibling_hash, side in proof:
        if side == 'left':
            # Sibling is on the left, current_hash is on the right.
            # Concatenate sibling + current_hash
            computed_hash = hash_data(sibling_hash + computed_hash)
        elif side == 'right':
            # Sibling is on the right, current_hash is on the left.
            # Concatenate current_hash + sibling
            computed_hash = hash_data(computed_hash + sibling_hash)
        else:
            # Should not happen with Literal type hint, but good practice
            print(f"Error: Invalid side '{side}' in proof step.") # Added error print for debugging
            return False # Invalid side information

    # After processing all proof steps, computed_hash should be the root
    return computed_hash == merkle_root

def extract_clauses(text: str) -> List[str]:
    """Extracts clauses while preserving spaces and formatting."""
    # Split by newline and filter out lines that are empty *after* stripping whitespace
    return [line for line in text.strip().split("\n") if line.strip()]

# --- Sample Data Sets ---
SAMPLE_DATASETS = [
    {
        "name": "Original Demo (Warranty Change & Typo)",
        "v1": """
Clause 1: The buyer agrees to pay in full within 30 days.
Clause 2: The seller provides a 1-year warranty.
Clause 3: All disputes will be settled in California.
""",
        "v2": """
Clause 1: The buyer agrees to pay in full within 30 days.
Clause 2: The seller provides a 2-year warranty.
Clause 3: All disputes will be settled in California .
"""
    },
    {
        "name": "Identical Contracts",
        "v1": """
Agreement: This is a test.
Term: For one year.
""",
        "v2": """
Agreement: This is a test.
Term: For one year.
"""
    },
    {
        "name": "Completely Different Contracts",
        "v1": """
Service: Web development.
Payment: $5000.
Deadline: 2 weeks.
""",
        "v2": """
Product: Software license.
Price: $200.
Support: Email only.
"""
    },
    {
        "name": "One Clause Added to V2",
        "v1": """
Section A: Initial terms.
Section B: Payment schedule.
""",
        "v2": """
Section A: Initial terms.
Section B: Payment schedule.
Section C: Confidentiality.
"""
    }
]

# Default contract texts for app.py, taken from the first sample dataset
contract_v1_default = SAMPLE_DATASETS[0]["v1"]
contract_v2_default = SAMPLE_DATASETS[0]["v2"]
