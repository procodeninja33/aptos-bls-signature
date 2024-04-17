module storage_bls::storage_check {
    use aptos_std::table;

    struct HashMsgs has key, store {
        /// mapping with hash
        hashes: table::Table<vector<u8>, bool>
    }

    fun init_module(owner_signer: &signer) {
        move_to(owner_signer, HashMsgs { hashes: table::new() });
    }

    public entry fun store_hash(hash: vector<u8>) acquires HashMsgs {
        let hash_msgs = borrow_global_mut<HashMsgs>(@storage_bls);
        if (table::contains(&hash_msgs.hashes, hash)) {
            table::add(&mut hash_msgs.hashes, hash, true);
        } else {
            // We don't want to fail the transaction we are just skipp it here
        }
    }

    /// remove will be failed if the hash not found in the table
    entry fun remove_hash(hash: vector<u8>) acquires HashMsgs {
        let hash_msgs = borrow_global_mut<HashMsgs>(@storage_bls);
        table::remove(&mut hash_msgs.hashes, hash);
    }

}
