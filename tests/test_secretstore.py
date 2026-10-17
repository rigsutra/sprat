"""Per-project secret store (sprat.secretstore): encryption at rest, key handling, storage edge cases."""
import base64
import hashlib
import json
import os
import stat
import sys
import threading
import time

import pytest
from cryptography.fernet import Fernet

import sprat.secretstore as ss
from sprat.secretstore import SecretStore, check_name


@pytest.fixture(autouse=True)
def no_env_key(monkeypatch):
    monkeypatch.delenv("SPRAT_SECRET_KEY", raising=False)


def _raw(tmp_path):
    return json.loads((tmp_path / "secrets.json").read_text(encoding="utf-8"))


# ---------- names ----------

@pytest.mark.parametrize("name", ["A", "a", "_X", "NTT_PASSWORD", "x1", "A" * 64, "camelCase_2"])
def test_valid_names(name):
    check_name(name)


@pytest.mark.parametrize("name", ["", None, "1A", "A" * 65, "A-B", "A B", "A.B", "${A}", "Ä", "\nA", "pass!"])
def test_invalid_names(name):
    with pytest.raises(ValueError, match="letters, digits and _"):
        check_name(name)


def test_name_with_trailing_newline_is_rejected():
    with pytest.raises(ValueError):
        check_name("PW\n")


def test_set_rejects_bad_name_before_touching_disk(tmp_path):
    with pytest.raises(ValueError):
        SecretStore(tmp_path / "d").set("p", "bad-name", "v")
    assert not (tmp_path / "d").exists()


def test_set_rejects_empty_value(tmp_path):
    with pytest.raises(ValueError, match="PW: enter a value"):
        SecretStore(tmp_path).set("p", "PW", "")
    assert not (tmp_path / "secrets.json").exists()


# ---------- key file ----------

def test_key_file_created_once_in_nested_dir_and_reused(tmp_path):
    d = tmp_path / "a" / "b"
    s = SecretStore(d)
    s.set("p", "K", "v")
    key = (d / ".secret.key").read_bytes()
    Fernet(key)  # a valid Fernet key
    SecretStore(d).set("p", "K2", "v2")
    assert (d / ".secret.key").read_bytes() == key
    assert SecretStore(d).values("p") == {"K": "v", "K2": "v2"}
    assert Fernet(key).decrypt(_raw(d)["p"]["K"]["value"].encode()) == b"v"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_key_and_secrets_files_are_private(tmp_path):
    SecretStore(tmp_path).set("p", "K", "v")
    for f in (".secret.key", "secrets.json"):
        assert stat.S_IMODE(os.stat(tmp_path / f).st_mode) == 0o600


def test_chmod_failures_are_ignored(tmp_path, monkeypatch):
    def deny(*a, **kw):
        raise OSError("not supported")
    monkeypatch.setattr(ss.os, "chmod", deny)
    s = SecretStore(tmp_path)
    s.set("p", "K", "v")
    assert s.values("p") == {"K": "v"}


def test_key_file_with_surrounding_whitespace(tmp_path):
    key = Fernet.generate_key()
    (tmp_path / ".secret.key").write_bytes(b"\n  " + key + b"\r\n")
    SecretStore(tmp_path).set("p", "K", "v")
    assert Fernet(key).decrypt(_raw(tmp_path)["p"]["K"]["value"].encode()) == b"v"


@pytest.mark.parametrize("content", [b"", b"not a key", b"\x00\xff" * 30])
def test_corrupt_key_file(tmp_path, content):
    (tmp_path / ".secret.key").write_bytes(content)
    with pytest.raises(ValueError):
        SecretStore(tmp_path).set("p", "K", "v")


def test_lost_key_file_makes_old_secrets_undecryptable(tmp_path):
    SecretStore(tmp_path).set("p", "K", "v")
    (tmp_path / ".secret.key").unlink()
    s = SecretStore(tmp_path)
    with pytest.raises(ValueError, match="Secret K can't be decrypted: the encryption key changed"):
        s.values("p")
    assert (tmp_path / ".secret.key").is_file()  # a new key was generated
    s.set("p", "K", "again")  # re-entering it fixes it
    assert s.values("p") == {"K": "again"}


def test_key_source(tmp_path, monkeypatch):
    assert SecretStore(tmp_path).key_source == str(tmp_path / ".secret.key")
    monkeypatch.setenv("SPRAT_SECRET_KEY", "x")
    assert SecretStore(tmp_path).key_source == "SPRAT_SECRET_KEY"


# ---------- SPRAT_SECRET_KEY ----------

def test_env_fernet_key_is_used_as_is(tmp_path, monkeypatch):
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("SPRAT_SECRET_KEY", key)
    SecretStore(tmp_path).set("p", "K", "value")
    assert Fernet(key).decrypt(_raw(tmp_path)["p"]["K"]["value"].encode()) == b"value"
    assert not (tmp_path / ".secret.key").exists()


@pytest.mark.parametrize("phrase", ["short", "a long passphrase for the server", "ünïcødé 🔑", "=" * 44])
def test_env_passphrase_is_hashed_into_a_key(tmp_path, monkeypatch, phrase):
    monkeypatch.setenv("SPRAT_SECRET_KEY", phrase)
    SecretStore(tmp_path).set("p", "K", "value")
    derived = Fernet(base64.urlsafe_b64encode(hashlib.sha256(phrase.encode()).digest()))
    assert derived.decrypt(_raw(tmp_path)["p"]["K"]["value"].encode()) == b"value"
    assert SecretStore(tmp_path).values("p") == {"K": "value"}


def test_switching_from_key_file_to_env_key(tmp_path, monkeypatch):
    SecretStore(tmp_path).set("p", "K", "v")
    monkeypatch.setenv("SPRAT_SECRET_KEY", "now a passphrase")
    with pytest.raises(ValueError, match="encryption key changed"):
        SecretStore(tmp_path).values("p")


def test_key_is_cached_per_instance(tmp_path, monkeypatch):
    s = SecretStore(tmp_path)
    s.set("p", "K", "v")
    monkeypatch.setenv("SPRAT_SECRET_KEY", "changed later")
    assert s.values("p") == {"K": "v"}  # same instance keeps its key


# ---------- storage ----------

@pytest.mark.parametrize("value", ["x", 'p@ss"w\\ord', "ünïcødé пароль 密码 🔑", "line1\nline2\ttab", " spaced ",
                                   "${NOT_EXPANDED}", "a" * 100_000, "\x00binary\x01"],
                         ids=["short", "quotes", "unicode", "controls", "spaces", "envref", "huge", "nul"])
def test_round_trip_and_never_plaintext_on_disk(tmp_path, value):
    SecretStore(tmp_path).set("proj", "PW", value)
    raw = (tmp_path / "secrets.json").read_bytes()
    if len(value.strip()) > 3:
        assert value.encode() not in raw and json.dumps(value)[1:-1].encode() not in raw
    assert SecretStore(tmp_path).values("proj") == {"PW": value}


def test_ciphertexts_differ_for_the_same_value(tmp_path):
    s = SecretStore(tmp_path)
    s.set("p", "A", "same")
    s.set("p", "B", "same")
    d = _raw(tmp_path)["p"]
    assert d["A"]["value"] != d["B"]["value"]


def test_names_sorted_with_timestamps_and_no_values(tmp_path, monkeypatch):
    t = [100.0]
    monkeypatch.setattr(ss.time, "time", lambda: t[0])
    s = SecretStore(tmp_path)
    s.set("p", "ZED", "1")
    t[0] = 200.0
    s.set("p", "ALPHA", "2")
    assert s.names("p") == [{"name": "ALPHA", "updated": 200.0}, {"name": "ZED", "updated": 100.0}]
    t[0] = 300.0
    s.set("p", "ZED", "3")  # overwrite
    assert s.names("p")[1] == {"name": "ZED", "updated": 300.0}
    assert s.values("p") == {"ALPHA": "2", "ZED": "3"}
    assert s.names("other") == []


def test_reads_before_anything_was_saved(tmp_path):
    s = SecretStore(tmp_path / "missing")
    assert s.names("p") == [] and s.values("p") == {}
    s.delete("p", "X")
    s.drop_project("p")
    assert not (tmp_path / "missing").exists()  # no file, no key, no dir


def test_projects_are_isolated(tmp_path):
    s = SecretStore(tmp_path)
    s.set("a", "PW", "for-a")
    s.set("b", "PW", "for-b")
    assert s.values("a") == {"PW": "for-a"} and s.values("b") == {"PW": "for-b"}
    s.delete("a", "PW")
    assert "a" not in _raw(tmp_path) and s.values("b") == {"PW": "for-b"}


def test_delete_keeps_other_names_and_unknown_is_a_no_op(tmp_path):
    s = SecretStore(tmp_path)
    s.set("p", "A", "1")
    s.set("p", "B", "2")
    s.delete("p", "A")
    assert s.values("p") == {"B": "2"}
    before = (tmp_path / "secrets.json").stat().st_mtime_ns
    s.delete("p", "NOPE")
    s.delete("other", "B")
    s.drop_project("other")
    assert (tmp_path / "secrets.json").stat().st_mtime_ns == before
    s.drop_project("p")
    assert _raw(tmp_path) == {}


def test_atomic_write_leaves_no_temp_file(tmp_path):
    SecretStore(tmp_path).set("p", "K", "v")
    assert sorted(f.name for f in tmp_path.iterdir()) == [".secret.key", "secrets.json"]


def test_corrupt_secrets_file(tmp_path):
    (tmp_path / "secrets.json").write_text("{not json", encoding="utf-8")
    s = SecretStore(tmp_path)
    for call in (lambda: s.names("p"), lambda: s.values("p"), lambda: s.set("p", "K", "v")):
        with pytest.raises(ValueError):
            call()


@pytest.mark.parametrize("bad", ["garbage", "", Fernet.generate_key().decode()])
def test_tampered_ciphertext(tmp_path, bad):
    s = SecretStore(tmp_path)
    s.set("p", "GOOD", "fine")
    s.set("p", "BAD", "x")
    data = _raw(tmp_path)
    data["p"]["BAD"]["value"] = bad
    (tmp_path / "secrets.json").write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="Secret BAD can't be decrypted"):
        SecretStore(tmp_path).values("p")
    assert SecretStore(tmp_path).names("p") == [{"name": "BAD", "updated": data["p"]["BAD"]["updated"]},
                                                 {"name": "GOOD", "updated": data["p"]["GOOD"]["updated"]}]


def test_flipped_byte_in_ciphertext_is_detected(tmp_path):
    s = SecretStore(tmp_path)
    s.set("p", "K", "value")
    data = _raw(tmp_path)
    tok = bytearray(base64.urlsafe_b64decode(data["p"]["K"]["value"]))
    tok[-40] ^= 1
    data["p"]["K"]["value"] = base64.urlsafe_b64encode(bytes(tok)).decode()
    (tmp_path / "secrets.json").write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="can't be decrypted"):
        SecretStore(tmp_path).values("p")


def test_entry_missing_updated_field(tmp_path):
    s = SecretStore(tmp_path)
    s.set("p", "K", "v")
    data = _raw(tmp_path)
    del data["p"]["K"]["updated"]
    (tmp_path / "secrets.json").write_text(json.dumps(data), encoding="utf-8")
    assert s.names("p") == [{"name": "K", "updated": None}]


# ---------- concurrency ----------

def test_concurrent_writes_on_one_store_lose_nothing(tmp_path):
    s = SecretStore(tmp_path)
    s.set("p", "WARMUP", "x")  # key exists before the race
    n = 24
    barrier = threading.Barrier(n)
    errors = []

    def worker(i):
        try:
            barrier.wait()
            s.set(f"p{i % 3}", f"K{i}", f"value-{i}")
        except Exception as e:  # pragma: no cover
            errors.append(e)
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(20)
    assert not errors
    fresh = SecretStore(tmp_path)
    got = {**fresh.values("p0"), **fresh.values("p1"), **fresh.values("p2")}
    assert got == {f"K{i}": f"value-{i}" for i in range(n)}


def test_concurrent_set_and_delete(tmp_path):
    s = SecretStore(tmp_path)
    for i in range(10):
        s.set("p", f"K{i}", "v")
    barrier = threading.Barrier(10)

    def worker(i):
        barrier.wait()
        s.delete("p", f"K{i}") if i % 2 else s.set("p", f"N{i}", "new")
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(20)
    assert sorted(s.values("p")) == sorted([f"K{i}" for i in range(0, 10, 2)] + [f"N{i}" for i in range(0, 10, 2)])


def test_key_file_created_by_another_process_first_is_waited_for_and_used(tmp_path, monkeypatch):
    # another process created .secret.key (create-exclusive) a moment ago and is still writing it
    key = Fernet.generate_key()
    kf = tmp_path / ".secret.key"
    kf.write_bytes(b"")
    real_is_file, first = ss.Path.is_file, [True]

    def is_file(self):
        if self == kf and first:
            first.clear()
            return False  # it didn't exist yet when this process looked
        return real_is_file(self)
    monkeypatch.setattr(ss.Path, "is_file", is_file)
    writer = threading.Timer(0.1, lambda: kf.write_bytes(key))
    writer.start()
    store = SecretStore(tmp_path)
    store.set("p", "PW", "value-1")
    writer.join()
    assert kf.read_bytes() == key  # the other process's key was kept, not overwritten
    monkeypatch.setenv("SPRAT_SECRET_KEY", key.decode())
    assert SecretStore(tmp_path).values("p") == {"PW": "value-1"}  # and the secret is encrypted with it


def test_concurrent_first_use_agrees_on_one_key(tmp_path, monkeypatch):
    real = Fernet.generate_key
    delays = iter([0.1, 0.5])
    lock = threading.Lock()

    def slow_key():  # a slow disk/CPU widens the window between the is_file() check and the write
        with lock:
            d = next(delays)
        time.sleep(d)
        return real()
    monkeypatch.setattr(ss.Fernet, "generate_key", staticmethod(slow_key))
    s = SecretStore(tmp_path)
    barrier = threading.Barrier(2)

    def worker(i):
        barrier.wait()
        s.set("p", f"K{i}", f"v{i}")
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(20)
    assert SecretStore(tmp_path).values("p") == {"K0": "v0", "K1": "v1"}
