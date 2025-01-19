
import os
import re
from ..modules.modules import ModuleDilithium
import time
from sympy import symbols, simplify, expand

try:
    from xoflib import shake256
except ImportError:
    from dilithium_py.shake.shake_wrapper import shake256


class Dilithium:
    def __init__(self, d, k, l, eta, tau, omega, gamma_1, gamma_2):
        self.d = d
        self.k = k
        self.l = l
        self.eta = eta
        self.tau = tau
        self.omega = omega
        self.gamma_1 = gamma_1
        self.gamma_2 = gamma_2
        self.beta = self.tau * self.eta

        self.M = ModuleDilithium()
        self.R = self.M.ring

        # Use system randomness by default, for deterministic randomness
        # use the method `set_drbg_seed()`
        self.random_bytes = os.urandom

    def set_drbg_seed(self, seed):
        """
        Change entropy source to a DRBG and seed it with provided value.

        Setting the seed switches the entropy source from :func:`os.urandom()`
        to an AES256 CTR DRBG.

        Used for both deterministic versions of Kyber as well as testing
        alignment with the KAT vectors

        Note:
          currently requires pycryptodome for AES impl.
        """
        try:
            from ..drbg.aes256_ctr_drbg import AES256_CTR_DRBG

            self._drbg = AES256_CTR_DRBG(seed)
            self.random_bytes = self._drbg.random_bytes
        except ImportError as e:  # pragma: no cover
            print(f"Error importing AES from pycryptodome: {e = }")
            raise Warning(
                "Cannot set DRBG seed due to missing dependencies, try installing requirements: pip -r install requirements"
            )

    """
    H() uses Shake256 to hash data to 32 and 64 bytes in a 
    few places in the code 
    """

    @staticmethod
    def _h(input_bytes, length):
        """
        H: B^*  -> B^*
        """
        return shake256(input_bytes).read(length)

    # For generating 'A' matrix from seed
    def _expand_matrix_from_seed(self, rho):
        """
        Helper function which generates a element of size
        k x l from a seed `rho`.
        """
        A_data = [[0 for _ in range(self.l)] for _ in range(self.k)]
        for i in range(self.k):
            for j in range(self.l):
                A_data[i][j] = self.R.rejection_sample_ntt_poly(rho, i, j)
        return self.M(A_data)

    ##############################
    ###### Original secret #######
    ##############################
    # # For generating 's1' and 's2' from seed
    # def _expand_vector_from_seed(self, rho_prime):
    #     # print("Secrets original")
    #     s1_elements = [
    #         self.R.rejection_bounded_poly(rho_prime, i, self.eta) for i in range(self.l)
    #     ]
    #     s2_elements = [
    #         self.R.rejection_bounded_poly(rho_prime, i, self.eta)
    #         for i in range(self.l, self.l + self.k)
    #     ]

    #     s1 = self.M.vector(s1_elements)
    #     s2 = self.M.vector(s2_elements)

    #     total_hamming_wt_s1 = 0
    #     total_hamming_wt_s2 = 0
    #     for i,polynomial in enumerate(s1._data[0]):
    #         hamming_wt = polynomial.calculate_polynomial_hamming_weight()
    #         total_hamming_wt_s1 += hamming_wt
    #     for i, polynomial in enumerate(s2._data[0]):
    #         hamming_wt = polynomial.calculate_polynomial_hamming_weight()
    #         total_hamming_wt_s2 += hamming_wt
    #     # print("S1 HW = ",total_hamming_wt_s1)
    #     # print("S2 HW = ",total_hamming_wt_s2)
    #     return s1, s2
    
    ####################################
    ### secrets to bound to hamming wt ###
    #####################################

    def _expand_vector_from_seed(self, rho_prime):
        safe_bound = 298  # Fixed safe bound
        s1_iterations_count = 0
        s2_iterations_count = 0

        # Find s1
        while True:  # Repeat until total Hamming weight of s1 satisfies the condition
            s1_iterations_count += 1
            modified_seed_s1 = f"{rho_prime}_{s1_iterations_count}".encode()

            # Generate s1 elements
            s1_elements = [
                self.R.rejection_bounded_poly(modified_seed_s1, i, self.eta) for i in range(self.l)
            ]
            s1 = self.M.vector(s1_elements)

            # Check total Hamming weight for s1
            total_hamming_weight_s1 = 0
            for poly_index, polynomial in enumerate(s1._data[0]):
                hamming_weight = polynomial.calculate_polynomial_hamming_weight()
                total_hamming_weight_s1 += hamming_weight

            if total_hamming_weight_s1 <= safe_bound * 4:
                # print(f"s1 found after {s1_iterations_count} iterations.")
                # print("S1 Total hamming wt = ",total_hamming_weight_s1)
                break  # Exit the loop when total Hamming weight is within the limit

        # Find s2
        while True:  # Repeat until total Hamming weight of s2 satisfies the condition
            s2_iterations_count += 1
            modified_seed_s2 = f"{rho_prime}_{s2_iterations_count}".encode()

            # Generate s2 elements
            s2_elements = [
                self.R.rejection_bounded_poly(modified_seed_s2, i, self.eta)
                for i in range(self.l, self.l + self.k)
            ]
            s2 = self.M.vector(s2_elements)

            # Check total Hamming weight for s2
            total_hamming_weight_s2 = 0
            for poly_index, polynomial in enumerate(s2._data[0]):
                hamming_weight = polynomial.calculate_polynomial_hamming_weight()
                total_hamming_weight_s2 += hamming_weight

            if total_hamming_weight_s2 <= safe_bound * 4:
                # print(f"s2 found after {s2_iterations_count} iterations.")
                # print("S2 Total hamming wt = ",total_hamming_weight_s2)
                break  # Exit the loop when total Hamming weight is within the limit

        return s1, s2



    ##############################
    ###### Modified secret #######
    ##############################
    # def _expand_vector_from_seed(self, rho_prime):
    #     s1_elements = [
    #         self.R.sample_in_ball(rho_prime+bytes([i]), self.tau) for i in range(self.l)
    #     ]
    #     s2_elements = [
    #         self.R.sample_in_ball(rho_prime+bytes([i]), self.tau)
    #         for i in range(self.l, self.l + self.k)
    #     ]

    #     # Convert the sampled elements into vector representations
    #     s1 = self.M.vector(s1_elements)
    #     s2 = self.M.vector(s2_elements)

    #     # Secret checking (For debugging)
    #     # print("s1:", s1)
    #     # print("s2:", s2)

    #     return s1, s2


    # For generating 'y'
    def _expand_mask_vector(self, rho_prime, kappa):
        elements = [
            self.R.sample_mask_polynomial(rho_prime, i, kappa, self.gamma_1)
            for i in range(self.l)
        ]
        return self.M.vector(elements)

    @staticmethod
    def _pack_pk(rho, t1):
        return rho + t1.bit_pack_t1()

    def _pack_sk(self, rho, K, tr, s1, s2, t0):
        s1_bytes = s1.bit_pack_s(self.eta)
        s2_bytes = s2.bit_pack_s(self.eta)
        t0_bytes = t0.bit_pack_t0()
        return rho + K + tr + s1_bytes + s2_bytes + t0_bytes

    # For generating 'h' (hint)
    def _pack_h(self, h):
        non_zero_positions = [
            [i for i, c in enumerate(poly.coeffs) if c == 1]
            for row in h._data
            for poly in row
        ]
        packed = []
        offsets = []
        for positions in non_zero_positions:
            packed.extend(positions)
            offsets.append(len(packed))

        padding_len = self.omega - offsets[-1]
        packed.extend([0 for _ in range(padding_len)])
        return bytes(packed + offsets)

    def _pack_sig(self, c_tilde, z, h):
        return c_tilde + z.bit_pack_z(self.gamma_1) + self._pack_h(h)

    def _unpack_pk(self, pk_bytes):
        rho, t1_bytes = pk_bytes[:32], pk_bytes[32:]
        t1 = self.M.bit_unpack_t1(t1_bytes, self.k, 1)
        return rho, t1

    def _unpack_sk(self, sk_bytes):
        if self.eta == 2:
            s_bytes = 96
        else:
            s_bytes = 128
        s1_len = s_bytes * self.l
        s2_len = s_bytes * self.k
        t0_len = 416 * self.k
        if len(sk_bytes) != 3 * 32 + s1_len + s2_len + t0_len:
            raise ValueError("SK packed bytes is of the wrong length")

        # Split bytes between seeds and vectors
        sk_seed_bytes, sk_vec_bytes = sk_bytes[:96], sk_bytes[96:]

        # Unpack seed bytes
        rho, K, tr = (
            sk_seed_bytes[:32],
            sk_seed_bytes[32:64],
            sk_seed_bytes[64:96],
        )

        # Unpack vector bytes
        s1_bytes = sk_vec_bytes[:s1_len]
        s2_bytes = sk_vec_bytes[s1_len : s1_len + s2_len]
        t0_bytes = sk_vec_bytes[-t0_len:]

        # Unpack bytes to vectors
        s1 = self.M.bit_unpack_s(s1_bytes, self.l, 1, self.eta)
        s2 = self.M.bit_unpack_s(s2_bytes, self.k, 1, self.eta)
        t0 = self.M.bit_unpack_t0(t0_bytes, self.k, 1)

        return rho, K, tr, s1, s2, t0

    def _unpack_h(self, h_bytes):
        offsets = [0] + list(h_bytes[-self.k :])
        non_zero_positions = [
            list(h_bytes[offsets[i] : offsets[i + 1]]) for i in range(self.k)
        ]

        matrix = []
        for poly_non_zero in non_zero_positions:
            coeffs = [0 for _ in range(256)]
            for non_zero in poly_non_zero:
                coeffs[non_zero] = 1
            matrix.append([self.R(coeffs)])
        return self.M(matrix)

    def _unpack_sig(self, sig_bytes):
        c_tilde = sig_bytes[:32]
        z_bytes = sig_bytes[32 : -(self.k + self.omega)]
        h_bytes = sig_bytes[-(self.k + self.omega) :]

        z = self.M.bit_unpack_z(z_bytes, self.l, 1, self.gamma_1)
        h = self._unpack_h(h_bytes)
        return c_tilde, z, h

    def keygen(self):
        """
        Generates a public-private keyair
        """
        # Random seed of 256 bits
        zeta = self.random_bytes(32) 

        # Expand with an XOF (SHAKE256) of 1024 bits
        seed_bytes = self._h(zeta, 128) 

        # Split bytes into suitable chunks
        rho, rho_prime, K = seed_bytes[:32], seed_bytes[32:96], seed_bytes[96:]

        # Generate matrix A ∈ R^(kxl) in the NTT domain
        A_hat = self._expand_matrix_from_seed(rho)

        # Generate the error vectors s1 ∈ R^l, s2 ∈ R^k
        s1, s2 = self._expand_vector_from_seed(rho_prime)

        # padded_s1 = [term for row in s1 for term in row] + [0] * (255 - len(s1))
        s1_hat = s1.to_ntt()

        # Matrix multiplication
        t = (A_hat @ s1_hat).from_ntt() + s2
        t1, t0 = t.power_2_round(self.d)

        # Pack up the bytes
        pk = self._pack_pk(rho, t1)
        tr = self._h(pk, 32)

        sk = self._pack_sk(rho, K, tr, s1, s2, t0)
        return pk, sk

    def sign(self, sk_bytes, m):
        """
        Generates a signature for a message m from a byte-encoded private key
        """
        # unpack the secret key
        rho, K, tr, s1, s2, t0 = self._unpack_sk(sk_bytes)

        # Generate matrix A ∈ R^(kxl) in the NTT domain
        A_hat = self._expand_matrix_from_seed(rho)

        # Set seeds and nonce (kappa) of 512 bits
        mu = self._h(tr + m, 64)
        kappa = 0
        rho_prime = self._h(K + mu, 64)

        # Precompute NTT representation
        s1 = s1.to_ntt()
        s2 = s2.to_ntt()
        t0 = t0.to_ntt()

        alpha = self.gamma_2 << 1
        while True:
            y = self._expand_mask_vector(rho_prime, kappa)
            y_hat = y.to_ntt()

            # increment the nonce
            kappa += self.l

            w = (A_hat @ y_hat).from_ntt()

            # Extract out both the high and low bits
            w1, w0 = w.decompose(alpha)

            # Create challenge polynomial
            w1_bytes = w1.bit_pack_w(self.gamma_2) # High bits
            c_tilde = self._h(mu + w1_bytes, 32)
            c = self.R.sample_in_ball(c_tilde, self.tau)

            # Store c in NTT form
            c = c.to_ntt()

            c_s1 = s1.scale(c).from_ntt()
            
            # print("Before update \n")
            # for i in range(len(c_s1._data)):
            #     print(f"c_s1 {i} = \n {c_s1._data[i]} \n")

            # update the coefficients
            for i in range(len(c_s1._data)):
                for idx, polynomial in enumerate(c_s1._data[i]):
                    c_s1._data[i][idx] = polynomial.update_polynomial_coefficients()
            
            # print("\n After update \n")
            # for i in range(len(c_s1._data)):
            #     print(f"c_s1 {i} = \n {c_s1._data[i]} \n")

            # Original
            # z = y + (s1.scale(c)).from_ntt() # scale is used to avoid overflow (To keep the result mod q)
            # Modified
            z = y + c_s1
            
            # Original
            # if z.check_norm_bound(self.gamma_1 - (self.beta)): # True if out of range
            # Modified
            if z.check_norm_bound(self.gamma_1 - round(self.beta / 2 ** 5)):
                continue

            c_s2 = s2.scale(c).from_ntt()

            # update the coefficients
            for i in range(len(c_s2._data)):
                for idx, polynomial in enumerate(c_s2._data[i]):
                    c_s2._data[i][idx] = polynomial.update_polynomial_coefficients()

            # w0_minus_cs2 = w0 - s2.scale(c).from_ntt()
            w0_minus_cs2 = w0 - c_s2

            # Original
            # if w0_minus_cs2.check_norm_bound(self.gamma_2 - (self.beta)): # True if out of range
            # Modified
            if w0_minus_cs2.check_norm_bound(self.gamma_2 - round(self.beta / 2**5)):
                continue

            c_t0 = t0.scale(c).from_ntt()
            if c_t0.check_norm_bound(self.gamma_2):
                continue

            w0_minus_cs2_plus_ct0 = w0_minus_cs2 + c_t0

            h = w0_minus_cs2_plus_ct0.make_hint_optimised(w1, alpha)
            """
            HB(w-cs2+ct0) = HB(w-cs2)
            HB(w-cs2) = HB(w) if LB(w-cs2) are small
            HB(w) = w1
            """
            if h.sum_hint() > self.omega:
                continue
            total_hw_z = 0
            for idx, polynomial in enumerate(z._data):
                hw = polynomial[0].calculate_polynomial_hamming_weight()
                total_hw_z += hw
            return self._pack_sig(c_tilde, z, h), total_hw_z
            return self._pack_sig(c_tilde, z, h)

    def verify(self, pk_bytes, m, sig_bytes):
        """
        Verifies a signature for a message m from a byte encoded public key and
        signature
        """
        rho, t1 = self._unpack_pk(pk_bytes)
        c_tilde, z, h = self._unpack_sig(sig_bytes)

        if h.sum_hint() > self.omega:
            return False

        if z.check_norm_bound(self.gamma_1 - self.beta):
            return False

        A_hat = self._expand_matrix_from_seed(rho)

        tr = self._h(pk_bytes, 32)
        mu = self._h(tr + m, 64)
        c = self.R.sample_in_ball(c_tilde, self.tau)

        # Convert to NTT for computation
        c = c.to_ntt()
        z = z.to_ntt()

        t1 = t1.scale(1 << self.d)
        t1 = t1.to_ntt()

        Az_minus_ct1 = (A_hat @ z) - t1.scale(c)
        Az_minus_ct1 = Az_minus_ct1.from_ntt()

        w_prime = h.use_hint(Az_minus_ct1, 2 * self.gamma_2)
        w_prime_bytes = w_prime.bit_pack_w(self.gamma_2)

        return c_tilde == self._h(mu + w_prime_bytes, 32)
