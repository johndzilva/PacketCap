# cipher_suites.py
# This file contains a mapping of TLS cipher suite codes to their human‑readable names,
# along with a flag indicating whether the suite is recommended by IANA and BSI (True) or not (False).

CIPHER_SUITES = {
    "0x0000": {
        "cipher": "TLS_NULL_WITH_NULL_NULL",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0001": {
        "cipher": "TLS_RSA_WITH_NULL_MD5",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0002": {
        "cipher": "TLS_RSA_WITH_NULL_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0003": {
        "cipher": "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0004": {
        "cipher": "TLS_RSA_WITH_RC4_128_MD5",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0005": {
        "cipher": "TLS_RSA_WITH_RC4_128_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0006": {
        "cipher": "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0007": {
        "cipher": "TLS_RSA_WITH_IDEA_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0008": {
        "cipher": "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0009": {
        "cipher": "TLS_RSA_WITH_DES_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x000a": {
        "cipher": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x000b": {
        "cipher": "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x000c": {
        "cipher": "TLS_DH_DSS_WITH_DES_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x000d": {
        "cipher": "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x000e": {
        "cipher": "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x000f": {
        "cipher": "TLS_DH_RSA_WITH_DES_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0010": {
        "cipher": "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0011": {
        "cipher": "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0012": {
        "cipher": "TLS_DHE_DSS_WITH_DES_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0013": {
        "cipher": "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0014": {
        "cipher": "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0015": {
        "cipher": "TLS_DHE_RSA_WITH_DES_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0016": {
        "cipher": "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0017": {
        "cipher": "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0018": {
        "cipher": "TLS_DH_anon_WITH_RC4_128_MD5",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0019": {
        "cipher": "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x001a": {
        "cipher": "TLS_DH_anon_WITH_DES_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x001b": {
        "cipher": "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x001e": {
        "cipher": "TLS_KRB5_WITH_DES_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x001f": {
        "cipher": "TLS_KRB5_WITH_3DES_EDE_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0020": {
        "cipher": "TLS_KRB5_WITH_RC4_128_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0021": {
        "cipher": "TLS_KRB5_WITH_IDEA_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0022": {
        "cipher": "TLS_KRB5_WITH_DES_CBC_MD5",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0023": {
        "cipher": "TLS_KRB5_WITH_3DES_EDE_CBC_MD5",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0024": {
        "cipher": "TLS_KRB5_WITH_RC4_128_MD5",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0025": {
        "cipher": "TLS_KRB5_WITH_IDEA_CBC_MD5",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0026": {
        "cipher": "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0027": {
        "cipher": "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0028": {
        "cipher": "TLS_KRB5_EXPORT_WITH_RC4_40_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0029": {
        "cipher": "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x002a": {
        "cipher": "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x002b": {
        "cipher": "TLS_KRB5_EXPORT_WITH_RC4_40_MD5",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x002c": {
        "cipher": "TLS_PSK_WITH_NULL_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x002d": {
        "cipher": "TLS_DHE_PSK_WITH_NULL_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x002e": {
        "cipher": "TLS_RSA_PSK_WITH_NULL_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x002f": {
        "cipher": "TLS_RSA_WITH_AES_128_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0030": {
        "cipher": "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0031": {
        "cipher": "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0032": {
        "cipher": "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0033": {
        "cipher": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0034": {
        "cipher": "TLS_DH_anon_WITH_AES_128_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0035": {
        "cipher": "TLS_RSA_WITH_AES_256_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0036": {
        "cipher": "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0037": {
        "cipher": "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0038": {
        "cipher": "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0039": {
        "cipher": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x003a": {
        "cipher": "TLS_DH_anon_WITH_AES_256_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x003b": {
        "cipher": "TLS_RSA_WITH_NULL_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x003c": {
        "cipher": "TLS_RSA_WITH_AES_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x003d": {
        "cipher": "TLS_RSA_WITH_AES_256_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x003e": {
        "cipher": "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2026
    },
    "0x003f": {
        "cipher": "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2026
    },
    "0x0040": {
        "cipher": "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2029
    },
    "0x0041": {
        "cipher": "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0042": {
        "cipher": "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0043": {
        "cipher": "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0044": {
        "cipher": "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0045": {
        "cipher": "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0046": {
        "cipher": "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0067": {
        "cipher": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2029
    },
    "0x0068": {
        "cipher": "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2026
    },
    "0x0069": {
        "cipher": "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2026
    },
    "0x006a": {
        "cipher": "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2029
    },
    "0x006b": {
        "cipher": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2029
    },
    "0x006c": {
        "cipher": "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x006d": {
        "cipher": "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0084": {
        "cipher": "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0085": {
        "cipher": "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0086": {
        "cipher": "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0087": {
        "cipher": "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0088": {
        "cipher": "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0089": {
        "cipher": "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x008a": {
        "cipher": "TLS_PSK_WITH_RC4_128_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x008b": {
        "cipher": "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x008c": {
        "cipher": "TLS_PSK_WITH_AES_128_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x008d": {
        "cipher": "TLS_PSK_WITH_AES_256_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x008e": {
        "cipher": "TLS_DHE_PSK_WITH_RC4_128_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x008f": {
        "cipher": "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0090": {
        "cipher": "TLS_DHE_PSK_WITH_AES_128_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0091": {
        "cipher": "TLS_DHE_PSK_WITH_AES_256_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0092": {
        "cipher": "TLS_RSA_PSK_WITH_RC4_128_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0093": {
        "cipher": "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0094": {
        "cipher": "TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0095": {
        "cipher": "TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0096": {
        "cipher": "TLS_RSA_WITH_SEED_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0097": {
        "cipher": "TLS_DH_DSS_WITH_SEED_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0098": {
        "cipher": "TLS_DH_RSA_WITH_SEED_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x0099": {
        "cipher": "TLS_DHE_DSS_WITH_SEED_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x009a": {
        "cipher": "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x009b": {
        "cipher": "TLS_DH_anon_WITH_SEED_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x009c": {
        "cipher": "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x009d": {
        "cipher": "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x009e": {
        "cipher": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        "IANA": True,
        "BSI": True,
        "BSI_ValidUpto": 2029
    },
    "0x009f": {
        "cipher": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        "IANA": True,
        "BSI": True,
        "BSI_ValidUpto": 2029
    },
    "0x00a0": {
        "cipher": "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2026
    },
    "0x00a1": {
        "cipher": "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2026
    },
    "0x00a2": {
        "cipher": "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2029
    },
    "0x00a3": {
        "cipher": "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2029
    },
    "0x00a4": {
        "cipher": "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2026
    },
    "0x00a5": {
        "cipher": "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2026
    },
    "0x00a6": {
        "cipher": "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x00a7": {
        "cipher": "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x00a8": {
        "cipher": "TLS_PSK_WITH_AES_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x00a9": {
        "cipher": "TLS_PSK_WITH_AES_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x00aa": {
        "cipher": "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
        "IANA": True,
        "BSI": True,
        "BSI_ValidUpto": 2029
    },
    "0x00ab": {
        "cipher": "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
        "IANA": True,
        "BSI": True,
        "BSI_ValidUpto": 2029
    },
    "0x00ac": {
        "cipher": "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2026
    },
    "0x00ad": {
        "cipher": "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2026
    },
    "0x00ae": {
        "cipher": "TLS_PSK_WITH_AES_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x00af": {
        "cipher": "TLS_PSK_WITH_AES_256_CBC_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x00b0": {
        "cipher": "TLS_PSK_WITH_NULL_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x00b1": {
        "cipher": "TLS_PSK_WITH_NULL_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x00b2": {
        "cipher": "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2029
    },
    "0x00b3": {
        "cipher": "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2029
    },
    "0x00b4": {
        "cipher": "TLS_DHE_PSK_WITH_NULL_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x00b5": {
        "cipher": "TLS_DHE_PSK_WITH_NULL_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x00b6": {
        "cipher": "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2026
    },
    "0x00b7": {
        "cipher": "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2026
    },
    "0x00b8": {
        "cipher": "TLS_RSA_PSK_WITH_NULL_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x00b9": {
        "cipher": "TLS_RSA_PSK_WITH_NULL_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x00ba": {
        "cipher": "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x00bb": {
        "cipher": "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x00bc": {
        "cipher": "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x00bd": {
        "cipher": "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x00be": {
        "cipher": "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x00bf": {
        "cipher": "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x00c0": {
        "cipher": "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x00c1": {
        "cipher": "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x00c2": {
        "cipher": "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x00c3": {
        "cipher": "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x00c4": {
        "cipher": "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x00c5": {
        "cipher": "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x00c6": {
        "cipher": "TLS_SM4_GCM_SM3",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x00c7": {
        "cipher": "TLS_SM4_CCM_SM3",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x1301": {
        "cipher": "TLS_AES_128_GCM_SHA256",
        "IANA": True,
        "BSI": True,
        "BSI_ValidUpto": 2031
    },
    "0x1302": {
        "cipher": "TLS_AES_256_GCM_SHA384",
        "IANA": True,
        "BSI": True,
        "BSI_ValidUpto": 2031
    },
    "0x1303": {
        "cipher": "TLS_CHACHA20_POLY1305_SHA256",
        "IANA": True,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x1304": {
        "cipher": "TLS_AES_128_CCM_SHA256",
        "IANA": True,
        "BSI": True,
        "BSI_ValidUpto": 2031
    },
    "0x1305": {
        "cipher": "TLS_AES_128_CCM_8_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x1306": {
        "cipher": "TLS_AEGIS_256_SHA512",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0x1307": {
        "cipher": "TLS_AEGIS_128L_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc001": {
        "cipher": "TLS_ECDH_ECDSA_WITH_NULL_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc002": {
        "cipher": "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc003": {
        "cipher": "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc004": {
        "cipher": "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc005": {
        "cipher": "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc006": {
        "cipher": "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc007": {
        "cipher": "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc008": {
        "cipher": "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc009": {
        "cipher": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc00a": {
        "cipher": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc00b": {
        "cipher": "TLS_ECDH_RSA_WITH_NULL_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc00c": {
        "cipher": "TLS_ECDH_RSA_WITH_RC4_128_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc00d": {
        "cipher": "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc00e": {
        "cipher": "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc00f": {
        "cipher": "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc010": {
        "cipher": "TLS_ECDHE_RSA_WITH_NULL_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc011": {
        "cipher": "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc012": {
        "cipher": "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc013": {
        "cipher": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc014": {
        "cipher": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc015": {
        "cipher": "TLS_ECDH_anon_WITH_NULL_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc016": {
        "cipher": "TLS_ECDH_anon_WITH_RC4_128_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc017": {
        "cipher": "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc018": {
        "cipher": "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc019": {
        "cipher": "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc01a": {
        "cipher": "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc01b": {
        "cipher": "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc01c": {
        "cipher": "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc01d": {
        "cipher": "TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc01e": {
        "cipher": "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc01f": {
        "cipher": "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc020": {
        "cipher": "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc021": {
        "cipher": "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc022": {
        "cipher": "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc023": {
        "cipher": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2031
    },
    "0xc024": {
        "cipher": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2031
    },
    "0xc025": {
        "cipher": "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2026
    },
    "0xc026": {
        "cipher": "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2026
    },
    "0xc027": {
        "cipher": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2031
    },
    "0xc028": {
        "cipher": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2031
    },
    "0xc029": {
        "cipher": "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2026
    },
    "0xc02a": {
        "cipher": "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2026
    },
    "0xc02b": {
        "cipher": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "IANA": True,
        "BSI": True,
        "BSI_ValidUpto": 2031
    },
    "0xc02c": {
        "cipher": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "IANA": True,
        "BSI": True,
        "BSI_ValidUpto": 2031
    },
    "0xc02d": {
        "cipher": "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2026
    },
    "0xc02e": {
        "cipher": "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2026
    },
    "0xc02f": {
        "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "IANA": True,
        "BSI": True,
        "BSI_ValidUpto": 2031
    },
    "0xc030": {
        "cipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "IANA": True,
        "BSI": True,
        "BSI_ValidUpto": 2031
    },
    "0xc031": {
        "cipher": "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2026
    },
    "0xc032": {
        "cipher": "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2026
    },
    "0xc033": {
        "cipher": "TLS_ECDHE_PSK_WITH_RC4_128_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc034": {
        "cipher": "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc035": {
        "cipher": "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc036": {
        "cipher": "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc037": {
        "cipher": "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2031
    },
    "0xc038": {
        "cipher": "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2031
    },
    "0xc039": {
        "cipher": "TLS_ECDHE_PSK_WITH_NULL_SHA",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc03a": {
        "cipher": "TLS_ECDHE_PSK_WITH_NULL_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc03b": {
        "cipher": "TLS_ECDHE_PSK_WITH_NULL_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc03c": {
        "cipher": "TLS_RSA_WITH_ARIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc03d": {
        "cipher": "TLS_RSA_WITH_ARIA_256_CBC_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc03e": {
        "cipher": "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc03f": {
        "cipher": "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc040": {
        "cipher": "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc041": {
        "cipher": "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc042": {
        "cipher": "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc043": {
        "cipher": "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc044": {
        "cipher": "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc045": {
        "cipher": "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc046": {
        "cipher": "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc047": {
        "cipher": "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc048": {
        "cipher": "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc049": {
        "cipher": "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc04a": {
        "cipher": "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc04b": {
        "cipher": "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc04c": {
        "cipher": "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc04d": {
        "cipher": "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc04e": {
        "cipher": "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc04f": {
        "cipher": "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc050": {
        "cipher": "TLS_RSA_WITH_ARIA_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc051": {
        "cipher": "TLS_RSA_WITH_ARIA_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc052": {
        "cipher": "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc053": {
        "cipher": "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc054": {
        "cipher": "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc055": {
        "cipher": "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc056": {
        "cipher": "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc057": {
        "cipher": "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc058": {
        "cipher": "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc059": {
        "cipher": "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc05a": {
        "cipher": "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc05b": {
        "cipher": "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc05c": {
        "cipher": "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc05d": {
        "cipher": "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc05e": {
        "cipher": "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc05f": {
        "cipher": "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc060": {
        "cipher": "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc061": {
        "cipher": "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc062": {
        "cipher": "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc063": {
        "cipher": "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc064": {
        "cipher": "TLS_PSK_WITH_ARIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc065": {
        "cipher": "TLS_PSK_WITH_ARIA_256_CBC_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc066": {
        "cipher": "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc067": {
        "cipher": "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc068": {
        "cipher": "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc069": {
        "cipher": "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc06a": {
        "cipher": "TLS_PSK_WITH_ARIA_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc06b": {
        "cipher": "TLS_PSK_WITH_ARIA_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc06c": {
        "cipher": "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc06d": {
        "cipher": "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc06e": {
        "cipher": "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc06f": {
        "cipher": "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc070": {
        "cipher": "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc071": {
        "cipher": "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc072": {
        "cipher": "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc073": {
        "cipher": "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc074": {
        "cipher": "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc075": {
        "cipher": "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc076": {
        "cipher": "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc077": {
        "cipher": "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc078": {
        "cipher": "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc079": {
        "cipher": "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc07a": {
        "cipher": "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc07b": {
        "cipher": "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc07c": {
        "cipher": "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc07d": {
        "cipher": "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc07e": {
        "cipher": "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc07f": {
        "cipher": "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc080": {
        "cipher": "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc081": {
        "cipher": "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc082": {
        "cipher": "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc083": {
        "cipher": "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc084": {
        "cipher": "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc085": {
        "cipher": "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc086": {
        "cipher": "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc087": {
        "cipher": "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc088": {
        "cipher": "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc089": {
        "cipher": "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc08a": {
        "cipher": "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc08b": {
        "cipher": "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc08c": {
        "cipher": "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc08d": {
        "cipher": "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc08e": {
        "cipher": "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc08f": {
        "cipher": "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc090": {
        "cipher": "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc091": {
        "cipher": "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc092": {
        "cipher": "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc093": {
        "cipher": "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc094": {
        "cipher": "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc095": {
        "cipher": "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc096": {
        "cipher": "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc097": {
        "cipher": "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc098": {
        "cipher": "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc099": {
        "cipher": "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc09a": {
        "cipher": "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc09b": {
        "cipher": "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc09c": {
        "cipher": "TLS_RSA_WITH_AES_128_CCM",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc09d": {
        "cipher": "TLS_RSA_WITH_AES_256_CCM",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc09e": {
        "cipher": "TLS_DHE_RSA_WITH_AES_128_CCM",
        "IANA": True,
        "BSI": True,
        "BSI_ValidUpto": 2029
    },
    "0xc09f": {
        "cipher": "TLS_DHE_RSA_WITH_AES_256_CCM",
        "IANA": True,
        "BSI": True,
        "BSI_ValidUpto": 2029
    },
    "0xc0a0": {
        "cipher": "TLS_RSA_WITH_AES_128_CCM_8",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc0a1": {
        "cipher": "TLS_RSA_WITH_AES_256_CCM_8",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc0a2": {
        "cipher": "TLS_DHE_RSA_WITH_AES_128_CCM_8",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc0a3": {
        "cipher": "TLS_DHE_RSA_WITH_AES_256_CCM_8",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc0a4": {
        "cipher": "TLS_PSK_WITH_AES_128_CCM",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc0a5": {
        "cipher": "TLS_PSK_WITH_AES_256_CCM",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc0a6": {
        "cipher": "TLS_DHE_PSK_WITH_AES_128_CCM",
        "IANA": True,
        "BSI": True,
        "BSI_ValidUpto": 2029
    },
    "0xc0a7": {
        "cipher": "TLS_DHE_PSK_WITH_AES_256_CCM",
        "IANA": True,
        "BSI": True,
        "BSI_ValidUpto": 2029
    },
    "0xc0a8": {
        "cipher": "TLS_PSK_WITH_AES_128_CCM_8",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc0a9": {
        "cipher": "TLS_PSK_WITH_AES_256_CCM_8",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc0aa": {
        "cipher": "TLS_PSK_DHE_WITH_AES_128_CCM_8",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc0ab": {
        "cipher": "TLS_PSK_DHE_WITH_AES_256_CCM_8",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc0ac": {
        "cipher": "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2031
    },
    "0xc0ad": {
        "cipher": "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
        "IANA": False,
        "BSI": True,
        "BSI_ValidUpto": 2031
    },
    "0xc0ae": {
        "cipher": "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc0af": {
        "cipher": "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc0b0": {
        "cipher": "TLS_ECCPWD_WITH_AES_128_GCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc0b1": {
        "cipher": "TLS_ECCPWD_WITH_AES_256_GCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc0b2": {
        "cipher": "TLS_ECCPWD_WITH_AES_128_CCM_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc0b3": {
        "cipher": "TLS_ECCPWD_WITH_AES_256_CCM_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc0b4": {
        "cipher": "TLS_SHA256_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc0b5": {
        "cipher": "TLS_SHA384_SHA384",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc100": {
        "cipher": "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc101": {
        "cipher": "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc102": {
        "cipher": "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc103": {
        "cipher": "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc104": {
        "cipher": "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc105": {
        "cipher": "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xc106": {
        "cipher": "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xcca8": {
        "cipher": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "IANA": True,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xcca9": {
        "cipher": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "IANA": True,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xccaa": {
        "cipher": "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "IANA": True,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xccab": {
        "cipher": "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xccac": {
        "cipher": "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
        "IANA": True,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xccad": {
        "cipher": "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
        "IANA": True,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xccae": {
        "cipher": "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xd001": {
        "cipher": "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
        "IANA": True,
        "BSI": True,
        "BSI_ValidUpto": 2031
    },
    "0xd002": {
        "cipher": "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
        "IANA": True,
        "BSI": True,
        "BSI_ValidUpto": 2031
    },
    "0xd003": {
        "cipher": "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256",
        "IANA": False,
        "BSI": False,
        "BSI_ValidUpto": None
    },
    "0xd005": {
        "cipher": "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",
        "IANA": True,
        "BSI": True,
        "BSI_ValidUpto": 2031
    }
}