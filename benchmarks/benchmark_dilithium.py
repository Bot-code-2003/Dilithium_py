import sys
import os
from statistics import mean, median

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))
from dilithium_py.dilithium import Dilithium2, Dilithium3, Dilithium5
from time import time


def benchmark_dilithium(Dilithium, name, count):
    # Banner
    print("-" * 27)
    print(f"  {name} | ({count} calls)")
    print("-" * 27)

    fails = 0
    keygen_times = []
    sign_times = []
    verify_times = []
    z_values = []

    # 32-byte message
    m = (
        b"Let me get this straight this is a secret message and a confidential "
        b"message that only I can send as I am the sole author of this message. "
        b"I am who I am and this is the this alphabet and english of the duolingo "
        b"and IELTS test. Hello! This is a test message to check functionality. "
        b"It contains some random words like apple, river, and sky. Let me know if it works properly!"
    )

    for _ in range(count):
        t0 = time()
        pk, sk = Dilithium.keygen()
        keygen_times.append(time() - t0)

        t1 = time()
        sig, z = Dilithium.sign(sk, m)
        sign_times.append(time() - t1)
        z_values.append(z)  # Collect z for averaging

        t2 = time()
        verify = Dilithium.verify(pk, m, sig)
        verify_times.append(time() - t2)
        if not verify:
            fails += 1

    # Compute averages and medians
    avg_keygen = round(mean(keygen_times), 3)
    median_keygen = round(median(keygen_times), 3)
    avg_sign = round(mean(sign_times), 3)
    median_sign = round(median(sign_times), 3)
    avg_verify = round(mean(verify_times), 3)
    median_verify = round(median(verify_times), 3)

    print(f"Keygen median: {median_keygen}")
    print(f"Keygen average: {avg_keygen}")
    print(f"Sign median: {median_sign}")
    print(f"Sign average: {avg_sign}")
    print(f"Verify median: {median_verify}")
    print(f"Fails: {fails}")

    # Compute the average of z
    # print(z_values)
    avg_z = sum(z_values) // len(z_values)
    print(f"Average z: {avg_z}")


if __name__ == "__main__":
    # Number of iterations
    count = 1

    print("Original s1 and s2")
    benchmark_dilithium(Dilithium2, "Dilithium2", count)
