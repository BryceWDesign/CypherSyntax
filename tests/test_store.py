from cyphersyntax.store import EncryptedStore


def test_encrypted_store_roundtrip(tmp_path):
    path = tmp_path / "state.bin"
    store = EncryptedStore(path=path, passphrase=b"correct horse battery staple")
    payload = {"node": "alpha", "counter": 7}
    store.save(payload)
    assert store.load() == payload
