import itertools
import secrets

import pytest
from cryptography.exceptions import InvalidTag

from burmalda.crypto import combine, seal, share_context, split, unseal


@pytest.mark.parametrize("pair", list(itertools.combinations(range(3), 2)))
def test_every_pair_recovers_and_authenticates(pair):
    context = share_context("client-a", "key-a", 1)
    key = secrets.token_bytes(32)
    parts = split(key, context)
    ciphertext = seal(key, {"full_name": "Синтетический клиент"}, context)
    restored = combine([parts[i] for i in pair], context)
    assert unseal(restored, ciphertext, context)["full_name"] == "Синтетический клиент"


def test_threshold_context_and_duplicate_indices():
    context = share_context("client-a", "key-a", 1)
    parts = split(secrets.token_bytes(32), context)
    with pytest.raises(ValueError, match="INSUFFICIENT_SHARES"):
        combine(parts[:1], context)
    with pytest.raises(ValueError, match="INVALID_SHARE_INDEX"):
        combine([parts[0], parts[0]], context)
    for field, value in (("client_id", "client-b"), ("version", 2), ("key_id", "key-b")):
        with pytest.raises(ValueError, match="SHARE_CONTEXT_MISMATCH"):
            combine([parts[0], {**parts[1], field: value}], context)


def test_old_key_and_changed_context_do_not_open_new_record():
    context = share_context("client-a", "key-a", 2)
    old_key, new_key = secrets.token_bytes(32), secrets.token_bytes(32)
    ciphertext = seal(new_key, {"passport": "SYNTHETIC"}, context)
    with pytest.raises(InvalidTag):
        unseal(old_key, ciphertext, context)
    with pytest.raises(InvalidTag):
        unseal(new_key, ciphertext, {**context, "client_id": "client-b"})
