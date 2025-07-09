import streamlit as st
import requests
import pandas as pd
import base64
from datetime import datetime, time
import pytz
from web3 import Web3

# api reference: https://safe-transaction-mainnet.safe.global/#/owners/owners_safes_retrieve
network_urls = {
    "mainnet": "https://safe-transaction-mainnet.safe.global/api",
    "gnosis": "https://safe-transaction-gnosis.safe.global/api"
}

# need to convert to checksummed 
def to_checksum_address(address):
    try:
        w3 = Web3()
        checksum_address = w3.to_checksum_address(address)
        return checksum_address, None
    except ValueError as e:
        return address, f"invalid: {e}"

def get_gnosis_safe_details(safe_address, network="mainnet"):
    base_url = network_urls[network]
    endpoint = f"{base_url}/v1/safes/{safe_address}/"
    
    try:
        response = requests.get(endpoint, timeout=10)
        if response.status_code == 200:
            data = response.json()
            owners = data.get("owners", [])
            threshold = data.get("threshold")
            if not owners:
                return safe_address, [], None, "no owners found"
            if threshold is None:
                return safe_address, owners, None, "no threshold"
            return safe_address, owners, threshold, None
        else:
            error_msg = f"error: {response.status_code}; {response.text}"
            if response.status_code == 422:
                error_msg += " (No fully capitalized or small letters! Checksummed address needed, eg 0x80D63b12aecF8aE5884cBF1d3536bb0C5f612CfC)"
            return safe_address, None, None, error_msg
    except requests.Timeout:
        return safe_address, None, None, "Timed out"
    except requests.RequestException as e:
        return safe_address, None, None, f"{e}"

def get_active_and_previous_signers(safe_address, network="mainnet", start_date=None, end_date=None):
    base_url = network_urls[network]
    endpoint = f"{base_url}/v1/safes/{safe_address}/multisig-transactions/"
    
    params = {}
    if start_date:
        params["executed_after"] = start_date.strftime("%Y-%m-%dT%H:%M:%SZ")
    if end_date:
        params["executed_before"] = end_date.strftime("%Y-%m-%dT%H:%M:%SZ")
    
    all_transactions = []
    active_transactions = []
    next_page = None
    try:
        while True:
            url = endpoint if not next_page else next_page
            response = requests.get(url, params=params if params else None, timeout=10)
            if response.status_code == 200:
                data = response.json()
                transactions = data.get("results", [])
                all_transactions.extend(transactions)
                if start_date and end_date:
                    for tx in transactions:
                        execution_date = tx.get("executionDate")
                        if execution_date:
                            try:
                                tx_date = datetime.fromisoformat(execution_date.replace("Z", "+00:00"))
                                if start_date <= tx_date <= end_date:
                                    active_transactions.append(tx)
                            except ValueError:
                                continue 
                else:
                    active_transactions.extend(transactions)
                next_page = data.get("next")
                if not next_page:
                    break
            else:
                error_msg = f"error: {response.status_code}; {response.text}"
                if response.status_code == 422:
                    error_msg += " (No fully capitalized or small letters! Checksummed address needed, eg 0x80D63b12aecF8aE5884cBF1d3536bb0C5f612CfC)"
                return None, None, error_msg
    except requests.Timeout:
        return None, None, "Timed out."
    except requests.RequestException as e:
        return None, None, f"{e}"
    
    active_signers = {}
    for tx in active_transactions:
        for conf in tx.get("confirmations", []):
            owner = conf["owner"]
            active_signers[owner] = active_signers.get(owner, 0) + 1
    
    added_owners = set()
    removed_owners = set()
    for tx in all_transactions:
        if "dataDecoded" in tx and tx["dataDecoded"]:
            method = tx["dataDecoded"].get("method")
            parameters = tx["dataDecoded"].get("parameters", [])
            if method == "addOwnerWithThreshold":
                for param in parameters:
                    if param["name"] == "owner" and param["type"] == "address":
                        added_owners.add(param["value"])
            elif method == "removeOwner":
                for param in parameters:
                    if param["name"] == "owner" and param["type"] == "address":
                        removed_owners.add(param["value"])
    
    previous_signers = list(removed_owners)
    return active_signers, previous_signers, None

def create_csv_download(results):
    data = []
    for address, network, owners, threshold, active_signers, previous_signers, error in results:
        if error or not owners:
            data.append({
                "Address": address,
                "Network": network,
                "Owner": "None",
                "Threshold": "N/A" if threshold is None else threshold,
                "Confirmations": 0,
                "Status": "N/A"
            })
        else:
            for owner in owners:
                confirmations = active_signers.get(owner, 0) if active_signers else 0
                data.append({
                    "Safe Address": address,
                    "Network": network,
                    "Owner": owner,
                    "Threshold": threshold,
                    "Confirmations": confirmations,
                    "Status": "Current"
                })
            for prev_owner in previous_signers or []:
                confirmations = active_signers.get(prev_owner, 0) if active_signers else 0
                data.append({
                    "Safe Address": address,
                    "Network": network,
                    "Owner": prev_owner,
                    "Threshold": threshold,
                    "Confirmations": confirmations,
                    "Status": "Previous"
                })
    
    df = pd.DataFrame(data)
    df = df.sort_values(by="Confirmations", ascending=False)
    csv = df.to_csv(index=False)
    b64 = base64.b64encode(csv.encode()).decode()
    return b64
    
st.title("Gnosis Safe Owners Lookup")
st.write("Enter Gnosis Safe addresses (one per line or comma-separated) to retrieve owners, threshold, and signers.")

# UI input options
with st.container():
    network = st.selectbox("Network", options=["mainnet", "gnosis"], index=0, help="Network where the Safe is deployed. Mainnet means EVM.")
    date_range = st.date_input(
        "Transaction Date Range",
        value=(datetime(2023, 1, 1), datetime.now()),
        min_value=datetime(2015, 1, 1),
        max_value=datetime.now(),
        help="Date range for signer activity."
    )
    start_date, end_date = date_range if isinstance(date_range, tuple) else (date_range, date_range)
    start_date = datetime.combine(start_date, time(0, 0)).replace(tzinfo=pytz.UTC)
    end_date = datetime.combine(end_date, time(23, 59, 59)).replace(tzinfo=pytz.UTC)
    addresses_input = st.text_area(
        "Safe Addresses",
        placeholder="eg, 0x80D63b12aecF8aE5884cBF1d3536bb0C5f612CfC\n0x4971DD016127F390a3EF6b956Ff944d0E2e1e462",
        height=100
    )

if st.button("Run"):
    if not addresses_input:
        st.error("Need at least one Gnosis Safe address")
    else:
        with st.spinner("Fetching data (may take awhile if multisig has many txns)..."):
            addresses = []
            for addr in addresses_input.replace(',', '\n').split('\n'):
                addr = addr.strip()
                if addr:
                    checksum_addr, error = to_checksum_address(addr)
                    if error:
                        st.error(f"**{addr}**: {error}")
                    else:
                        addresses.append(checksum_addr)
            
            if not addresses:
                st.error("no valid addresses")
            else:
                results = []
                for addr in addresses:
                    address, owners, threshold, error = get_gnosis_safe_details(addr, network)
                    active_signers = None
                    previous_signers = None
                    active_error = None
                    if not error:
                        active_signers, previous_signers, active_error = get_active_and_previous_signers(
                            addr, network, start_date, end_date
                        )
                        if active_error:
                            error = active_error
                    results.append((address, network, owners, threshold, active_signers, previous_signers, error))
                
                st.subheader("Results")
                
                # CSV download link at the top
                if results:
                    b64 = create_csv_download(results)
                    st.markdown(
                        f'<a href="data:file/csv;base64,{b64}" download="gnosis_safe_details.csv">Download CSV</a>',
                        unsafe_allow_html=True
                    )
                    st.markdown("---")  # Separator for clarity
                
                # Display individual Safe details
                for address, network, owners, threshold, active_signers, previous_signers, error in results:
                    with st.container():
                        if error:
                            st.error(f"**{address}** on {network}: {error}")
                            if "422" in error:
                                st.info("Non-checksummed address")
                        else:
                            st.markdown(f"**{address}** (Network: {network}, Threshold: {threshold})")
                            # Current Owners
                            st.markdown("**Current Owners**:")
                            if owners:
                                for owner in owners:
                                    st.markdown(f"- {owner}")
                            else:
                                st.warning("No current owners found.")
                            # Previous Signers
                            if previous_signers:
                                st.markdown(f"**Previous Signers**: {', '.join(previous_signers)}")
                            else:
                                st.markdown("**Previous Signers**: None")
                            
                            data = []
                            for owner in owners or []:
                                data.append({
                                    "Owner Address": owner,
                                    "Confirmations": active_signers.get(owner, 0) if active_signers else 0,
                                    "Status": "Current"
                                })
                            for prev_owner in previous_signers or []:
                                data.append({
                                    "Owner Address": prev_owner,
                                    "Confirmations": active_signers.get(prev_owner, 0) if active_signers else 0,
                                    "Status": "Previous"
                                })
                            df_owners = pd.DataFrame(data) if data else pd.DataFrame(columns=["Owner Address", "Confirmations", "Status"])
                            if active_signers is not None:
                                df_owners = df_owners.sort_values(by="Confirmations", ascending=False)
                                st.markdown(f"**Date range**: {start_date.date()} to {end_date.date()}")
                            else:
                                st.markdown("**Date range**: No txn data available")
                            st.dataframe(df_owners, use_container_width=True)
