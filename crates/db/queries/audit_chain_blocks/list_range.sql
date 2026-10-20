-- class: infra. params: from_start, to_start (exclusive), after_start, limit
SELECT block_start, block_end, first_id, last_id, event_count, merkle_root, prev_block_hash, block_hash,
       anchored_blob_key, anchored_blob_write_id, anchored_blob_digest, sealed_at
FROM audit_chain_blocks WHERE block_start >= ? AND block_start < ? AND block_start > ?
ORDER BY block_start LIMIT ?
