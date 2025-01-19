from .dilithium import Dilithium
import time

DEFAULT_PARAMETERS = {
    "dilithium2": {
        "d": 13,
        "k": 4,
        "l": 4,
        "eta": 2,
        "tau": 39,
        "omega": 80,
        "gamma_1": 131072,  # 2^17
        "gamma_2": 95232,  # (q-1)/88
    },
    "dilithium3": {
        "d": 13,
        "k": 6,
        "l": 5,
        "eta": 4,
        "tau": 49,
        "omega": 55,
        "gamma_1": 524288,  # 2^19
        "gamma_2": 261888,  # (q-1)/32
    },
    "dilithium5": {
        "d": 13,
        "k": 8,
        "l": 7,
        "eta": 2,
        "tau": 60,
        "omega": 75,
        "gamma_1": 524288,  # 2^19
        "gamma_2": 261888,  # (q-1)/32
    },
}

Dilithium2 = Dilithium(**DEFAULT_PARAMETERS["dilithium2"])
Dilithium3 = Dilithium(**DEFAULT_PARAMETERS["dilithium3"])
Dilithium5 = Dilithium(**DEFAULT_PARAMETERS["dilithium5"])

if __name__ == "__main__":
    print("Testing default parameters...")

    message = b"This is a secret message!"

    print("\nUsing Dilithium2:")
    public_key, private_key = Dilithium2.keygen()

    # Signing and extracting z
    signature, z = Dilithium2.sign(private_key, message)

    # Verifying the signature
    is_valid = Dilithium2.verify(public_key, message, signature)
    print("Signature Valid?", is_valid)

    # You can do similar updates for Dilithium3 and Dilithium5 if needed
    # print("\nUsing Dilithium3:")
    # public_key, private_key = Dilithium3.keygen()
    # signature, z = Dilithium3.sign(private_key, message)
    # print("z:", z)
    # is_valid = Dilithium3.verify(public_key, message, signature)
    # print("Signature Valid?", is_valid)

    # print("\nUsing Dilithium5:")
    # public_key, private_key = Dilithium5.keygen()
    # signature, z = Dilithium5.sign(private_key, message)
    # print("z:", z)
    # is_valid = Dilithium5.verify(public_key, message, signature)
    # print("Signature Valid?", is_valid)
