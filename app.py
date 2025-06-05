import streamlit as st
import contractVerification as cv

st.title("Contract Merkle Verification Demo")

st.sidebar.header("Load Sample Data")
sample_names = [ds["name"] for ds in cv.SAMPLE_DATASETS]

if "selected_sample_name" not in st.session_state:
    st.session_state.selected_sample_name = sample_names[0] # Default to first sapmle
    st.session_state.v1_text_content = cv.SAMPLE_DATASETS[0]["v1"]
    st.session_state.v2_text_content = cv.SAMPLE_DATASETS[0]["v2"]

def load_sample():
    selected_dataset = next(ds for ds in cv.SAMPLE_DATASETS if ds["name"] == st.session_state.selected_sample_name)
    st.session_state.v1_text_content = selected_dataset["v1"]
    st.session_state.v2_text_content = selected_dataset["v2"]

st.sidebar.selectbox(
    "Choose a sample contract set:",
    options=sample_names,
    key="selected_sample_name",
    on_change=load_sample
)

st.header("Enter Contract Texts")
col1, col2 = st.columns(2)
with col1:
    contract_text_v1 = st.text_area("Contract Version 1", height=200, key="v1_text_content")
with col2:
    contract_text_v2 = st.text_area("Contract Version 2", height=200, key="v2_text_content")

if st.button("Compare Contracts"):
    if not contract_text_v1.strip() or not contract_text_v2.strip():
        st.warning("Please provide text for both contracts.")
    else:
        clauses_v1 = cv.extract_clauses(contract_text_v1)
        clauses_v2 = cv.extract_clauses(contract_text_v2)

        if not clauses_v1 or not clauses_v2:
            st.error("Could not extract clauses from one or both contracts. Ensure each clause is on a new line and the contract is not empty.")
        else:
            hashes_v1 = [cv.hash_data(c) for c in clauses_v1]
            tree_v1 = cv.build_merkle_tree(hashes_v1)
            root_v1 = cv.get_merkle_root(tree_v1)

            hashes_v2 = [cv.hash_data(c) for c in clauses_v2]
            tree_v2 = cv.build_merkle_tree(hashes_v2)
            root_v2 = cv.get_merkle_root(tree_v2)

            st.subheader("Merkle Roots")
            st.write(f"**V1 Root:** `{root_v1}`")
            st.write(f"**V2 Root:** `{root_v2}`")

            if cv.compare_merkle_roots(root_v1, root_v2):
                st.success("✅ Contracts are IDENTICAL based on Merkle roots.")
            else:
                st.error("❌ Contracts are DIFFERENT based on Merkle roots.")
                report = cv.get_clause_comparison_report(hashes_v1, hashes_v2, clauses_v1, clauses_v2)
                st.text_area("Clause-Level Difference Report", value="\n".join(report), height=250, key="diff_report")