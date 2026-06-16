"""Deserialization sink for the chain (separate file so the chain spans modules).

INTENTIONALLY-VULNERABLE TEST FIXTURE. Do NOT deploy.
"""
import pickle


def deserialize(content):
    """Deserialize raw bytes into a Python object.

    The bytes originate from the attacker-controlled URL fetched in core/views.py
    proxy() (SSRF source). This is the dangerous SINK of the cross-file chain.
    """
    # CHAIN step 2/2 (insecure deserialization -> RCE) — sink in core/ingest.py
    return pickle.loads(content)
