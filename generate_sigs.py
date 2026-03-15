import struct

def create_sig_bin(output_path):
    magic = b"GXSIG001"
    version = 1

    malware_data = [
        ("138551cd967622832f8a816ea1697a5d08ee66c379d32d8a6bd7fca9fdeaecc4", "Trojan.AndroidOS.GodFather.a", "GodFather"),
        ("91642870eb3d10b1a5bc427d00dc484f00ead67aa1ebd547d040e765b9126e65", "Trojan.AndroidOS.MoqHao.b", "MoqHao"),
        ("495a0621b2afc6adefbf17dc6c3cf5e92ba8227ac6939a20439b1b9dde878617", "Trojan.AndroidOS.Ermac.c", "Ermac"),
        ("cb25b1664a856f0c3e71a318f3e35eef8b331e047acaf8c53320439c3c23ef7c", "BankBot.AndroidOS.YNRK.a", "BankBot"),
        ("19456fbe07ae3d5dc4a493bac27921b02fc75eaa02009a27ab1c6f52d0627423", "BankBot.AndroidOS.YNRK.b", "BankBot"),
        ("a4126a8863d4ff43f4178119336fa25c0c092d56c46c633dc73e7fc00b4d0a07", "BankBot.AndroidOS.YNRK.c", "BankBot"),
        ("153410238d01773e5c705c6d18955793bd61cb2e82c5c7656e74563bb43b3ffa", "Trojan.AndroidOS.Chameleon.a", "Chameleon"),
        ("003df8738942a88d690aeb902744cec2dc2e671c708e96cb1085b13bdbd6823a", "Malware.AndroidOS.Generic.100", "Generic"),
        ("03861103d6b64a9d11bfadcd674b3be46528ea88fbea4adfb1a33fc9cec29479", "Malware.AndroidOS.Generic.101", "Generic"),
        ("0496f43dcc6c2e25bbf6d05a13e72dadc2ae6397fc617c935fd865f243ffd084", "Malware.AndroidOS.Generic.102", "Generic"),
    ]

    record_count = len(malware_data)

    with open(output_path, "wb") as f:
        f.write(magic)
        f.write(struct.pack("<II", version, record_count))

        for sha256, name, family in malware_data:
            severity = 2 # MALWARE
            f.write(struct.pack("B", severity))

            # SHA256: 64 chars + null
            f.write(sha256.lower().encode("ascii") + b"\x00")
            # MD5: 32 chars + null (empty for now)
            f.write(b"0" * 32 + b"\x00")

            name_bytes = name.encode("utf-8")
            f.write(struct.pack("<H", len(name_bytes)))
            f.write(name_bytes)

            family_bytes = family.encode("utf-8")
            f.write(struct.pack("<H", len(family_bytes)))
            f.write(family_bytes)

create_sig_bin("app/src/main/assets/signatures.bin")
