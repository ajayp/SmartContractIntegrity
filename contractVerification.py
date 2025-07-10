import hashlib
from typing import List, Tuple, Literal
import re

try:
    import graphviz
except ImportError:
    graphviz = None

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

    # Helper to strip "Clause X:" or "Section Y:" prefixes for cleaner reporting
    clean_clause = lambda c: re.sub(r"^(clause|section)\s*\w*:\s*", "", c, flags=re.IGNORECASE).strip()

    # Helper to get a descriptive label for a clause, including its line number
    def get_label(clause_text: str, line_number: int) -> str:
        # Try to find a "Clause X" or "Section Y" style prefix
        match = re.match(r"^((?:Clause|Section)\s*\w*)", clause_text, re.IGNORECASE)
        if match:
            # Use the found label and add the line number for clarity, e.g., "Clause 3 (Line 4)"
            return f"{match.group(1).strip()} (Line {line_number})"
        # If no specific label is found, just use the line number
        return f"Line {line_number}"

    for i in range(min_len):
        h1 = hashes_v1[i]
        h2 = hashes_v2[i]
        label = get_label(clauses_v1[i], i + 1)
        if h1 == h2:
            report_lines.append(f"{label}: ✅ Match")
        else:
            report_lines.append(f"{label}: ❌ Difference")
            report_lines.append(f"   🔹 V1: {clean_clause(clauses_v1[i])}")
            report_lines.append(f"   🔹 V2: {clean_clause(clauses_v2[i])}")

    # Report clauses only present in the longer version
    if max_len > min_len:
        report_lines.append("Additional Clauses:")
        if len(hashes_v1) > len(hashes_v2):
            report_lines.append("   🔹 V1 has additional clauses:")
            for i in range(min_len, max_len):
                label = get_label(clauses_v1[i], i + 1)
                report_lines.append(f"      {label}: {clean_clause(clauses_v1[i])}")
        else:
            report_lines.append("   🔹 V2 has additional clauses:")
            for i in range(min_len, max_len):
                 label = get_label(clauses_v2[i], i + 1)
                 report_lines.append(f"      {label}: {clean_clause(clauses_v2[i])}")
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

    proof: MerkleProof = []
    current_hash_up = target_hash

    for level_index in range(len(tree) - 1):  # Iterate up to the level before the root
        level = tree[level_index]
        found_in_level = False
        for i in range(0, len(level), 2):
            left_node = level[i]
            # Handle odd number of nodes by duplicating the last one, matching build_merkle_tree
            right_node = level[i + 1] if i + 1 < len(level) else level[i]

            if current_hash_up == left_node:
                # Target is the left node, sibling is the right
                # Append the sibling hash and its side ('right')
                proof.append((right_node, 'right'))
                # Compute the parent hash for the next iteration (left + right)
                current_hash_up = hash_data(left_node + right_node)
                found_in_level = True
                break  # Move to the next level up
            elif current_hash_up == right_node:
                 # Target is the right node, sibling is the left
                 # Append the sibling hash and its side ('left')
                 proof.append((left_node, 'left'))
                 # Compute the parent hash for the next iteration (still left + right order as per build)
                 current_hash_up = hash_data(left_node + right_node)
                 found_in_level = True
                 break  # Move to the next level up

        if not found_in_level:
            # This means the current_hash_up was not found in the expected level.
            # This could indicate an invalid target_hash or a broken tree structure.
            # For a POC, we can return an empty proof.
            return []

    # After the loop, current_hash_up should be the root.
    # The verification function will compare this computed root with the expected root.
    return proof


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
    return [line for line in text.split('\n') if line.strip()]

def generate_merkle_tree_visualization(tree: List[List[str]], title: str, clauses: List[str] = None):
    """Generates a Graphviz object for visualizing the Merkle Tree."""
    if not graphviz:
        # Return None if the library is not installed. The app will handle this.
        return None

    if not tree:
        return None

    dot = graphviz.Digraph(comment=title)
    dot.attr(label=title, labelloc='t', fontsize='20', fontname="Helvetica")
    dot.attr('node', shape='box', style='rounded,filled', fillcolor='lightblue', fontname="Helvetica")
    dot.attr('edge', arrowhead='vee')

    # Create a unique ID for each node based on its hash to avoid collisions
    node_ids = {h: f'node_{h[:8]}' for level in tree for h in level}

    # Create a mapping from leaf hash to original clause text for tooltips
    leaf_hashes = tree[0] if tree else []
    hash_to_clause = {}
    if clauses and len(clauses) == len(leaf_hashes):
        hash_to_clause = {leaf_hashes[i]: clauses[i] for i in range(len(leaf_hashes))}

    # Add nodes to the graph
    for h, node_id in node_ids.items():
        # Use a truncated hash for cleaner labels
        label = f'{h[:10]}...'
        # Set the tooltip: clause text for leaves, full hash for internal/root nodes
        tooltip_text = hash_to_clause.get(h, h)
        # Use a different color for leaf nodes vs. internal nodes
        fill_color = 'lightyellow' if h in hash_to_clause else 'lightblue'
        dot.node(node_id, label=label, tooltip=tooltip_text, fillcolor=fill_color)

    # Add edges connecting parents to children
    for level_index in range(len(tree) - 1):
        parent_level = tree[level_index + 1]
        child_level = tree[level_index]
        parent_index = 0
        for i in range(0, len(child_level), 2):
            left_child_hash = child_level[i]
            # Handle odd number of nodes by linking parent to the duplicated node
            right_child_hash = child_level[i + 1] if i + 1 < len(child_level) else left_child_hash
            
            parent_hash = parent_level[parent_index]
            parent_index += 1

            # Connect parent to its children
            dot.edge(node_ids[parent_hash], node_ids[left_child_hash])
            if left_child_hash != right_child_hash: # Avoid drawing a second edge to a duplicated node
                dot.edge(node_ids[parent_hash], node_ids[right_child_hash])

    # Highlight the root node in a different color
    if tree[-1]:
        root_hash = tree[-1][0]
        dot.node(node_ids[root_hash], fillcolor='lightgreen')

    return dot

# --- Sample Data Sets ---
SAMPLE_DATASETS = [
    {
        "name": "Warranty Change",
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

if __name__ == '__main__':
    # This block runs only when the script is executed directly (e.g., `python contractVerification.py`)
    # It serves as a simple demonstration of the module's capabilities.
    print("--- Running contractVerification.py as a standalone script ---")

    # Use the first sample dataset for a quick demo
    v1_text = SAMPLE_DATASETS[0]["v1"]
    v2_text = SAMPLE_DATASETS[0]["v2"]

    print("\n--- Contract V1 ---")
    print(v1_text.strip())
    print("\n--- Contract V2 ---")
    print(v2_text.strip())

    # 1. Extract clauses
    clauses1 = extract_clauses(v1_text)
    clauses2 = extract_clauses(v2_text)

    # 2. Generate hashes and build trees
    hashes1 = [hash_data(c) for c in clauses1]
    tree1 = build_merkle_tree(hashes1)
    root1 = get_merkle_root(tree1)

    hashes2 = [hash_data(c) for c in clauses2]
    tree2 = build_merkle_tree(hashes2)
    root2 = get_merkle_root(tree2)

    print(f"\n--- Merkle Roots ---")
    print(f"V1 Root: {root1}")
    print(f"V2 Root: {root2}")

    # 3. Compare roots and report differences
    if compare_merkle_roots(root1, root2):
        print("\n✅ Result: Contracts are IDENTICAL.")
    else:
        print("\n❌ Result: Contracts are DIFFERENT.")
        report = get_clause_comparison_report(hashes1, hashes2, clauses1, clauses2)
        print("\n".join(report))

    # 4. Demonstrate Merkle Proof generation and verification
    if clauses1:
        target_clause_hash = hashes1[0]
        proof = get_merkle_proof(tree1, target_clause_hash)
        is_valid = verify_merkle_proof(proof, target_clause_hash, root1)
        print("\n--- Merkle Proof Demo ---")
        print(f"Verifying first clause of V1...")
        print(f"Proof is valid: {is_valid}")
