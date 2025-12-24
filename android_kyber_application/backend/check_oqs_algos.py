import oqs
print("Enabled Signature Mechanisms:")
try:
    sigs = oqs.get_enabled_sig_mechanisms()
    for s in sigs:
        print(s)
except Exception as e:
    print(f"Error: {e}")
