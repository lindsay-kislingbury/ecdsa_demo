import os
import time
import tkinter as tk
from tkinter import ttk, scrolledtext

# using cryptography library for ecdsa and rsa
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


class ECDSAvsRSADemo:
    def __init__(self, root):
        self.root = root
        root.title("ECDSA vs RSA for Bitcoin")
        root.geometry("1000x800")

        self.font = ("Arial", 16)
        self.heading_font = ("Arial", 22, "bold")
        self.button_font = ("Arial", 18, "bold")
        self.frame_title_font = ("Arial", 18, "bold")

        # configure a style for larger buttons
        style = ttk.Style()
        style.configure("Big.TButton", font=self.button_font)

        main_frame = ttk.Frame(root, padding=10)
        main_frame.pack(fill="both", expand=True)

        tk.Label(
            main_frame,
            text="ECDSA vs RSA Performance Comparison",
            font=self.heading_font,
        ).pack(pady=10)

        desc = ttk.LabelFrame(main_frame, padding=10)
        desc.pack(fill="x", pady=5)
        ttk.Label(
            desc,
            text="Compares ECDSA versus RSA at equivalent security (256-bit ECDSA using secp256k1 curve vs 3072 bit RSA).",
            font=self.frame_title_font,
        ).pack(anchor="w", pady=5)

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill="x", pady=5)

        self.iterations = 100
        self.run_btn = ttk.Button(
            btn_frame,
            text=f"Run Benchmark ({self.iterations} operations)",
            command=self.run_benchmark,
            style="Big.TButton",
        )
        self.run_btn.pack(pady=5)

        self.progress_var = tk.StringVar(value="Click button to start benchmark")
        ttk.Label(btn_frame, textvariable=self.progress_var, font=self.font).pack(
            pady=2
        )

        results_frame = ttk.LabelFrame(main_frame, padding=5)
        results_frame.pack(fill="x", pady=5)
        ttk.Label(
            results_frame, text="Benchmark Results", font=self.frame_title_font
        ).pack(anchor="w", pady=2)
        self.results_text = scrolledtext.ScrolledText(
            results_frame,
            height=4,
            width=90,
            wrap="word",
            font=self.font,
        )
        self.results_text.pack(fill="x", pady=2)

        graph_frame = ttk.LabelFrame(main_frame, padding=10)
        graph_frame.pack(fill="both", expand=True, pady=10)
        ttk.Label(
            graph_frame, text="Performance Metrics", font=self.frame_title_font
        ).pack(anchor="w", pady=5)

        self.fig, self.ax = plt.subplots(2, 2, figsize=(10, 5))
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

        for ax in self.ax.flat:
            ax.set_title("No data yet")
        self.fig.tight_layout()
        self.canvas.draw()

        self.generate_keys()

    def generate_keys(self):
        self.progress_var.set("Generating keys...")
        self.root.update()

        # generate ecdsa keys (bitcoin uses secp256k1)
        self.ecdsa_private_key = ec.generate_private_key(ec.SECP256K1())
        self.ecdsa_public_key = self.ecdsa_private_key.public_key()

        # generate rsa keys (3072 bits = 256-bit ecc security)
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=3072
        )
        self.rsa_public_key = self.rsa_private_key.public_key()

        # get key sizes for comparison
        self.ecdsa_pubkey = self.ecdsa_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )
        self.rsa_pubkey = self.rsa_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # warm-up crypto operations
        temp_hash = os.urandom(32)
        for _ in range(3):
            self.ecdsa_private_key.sign(temp_hash, ec.ECDSA(hashes.SHA256()))
            self.rsa_private_key.sign(
                temp_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

        self.progress_var.set("Keys generated - ready to run benchmark")

    def run_benchmark(self):
        self.run_btn.config(state="disabled")
        self.progress_var.set("Running benchmark...")
        self.root.update()

        # generate random data to sign
        data = [os.urandom(32) for _ in range(self.iterations)]

        # run benchmarks
        ecdsa_sigs, ecdsa_sign_time = self.benchmark_ecdsa_signing(data)
        rsa_sigs, rsa_sign_time = self.benchmark_rsa_signing(data)
        ecdsa_verify_time, rsa_verify_time = self.benchmark_verification(
            data, ecdsa_sigs, rsa_sigs
        )

        # calculate metrics
        ecdsa_sig_size = sum(len(sig) for sig in ecdsa_sigs) / len(ecdsa_sigs)
        rsa_sig_size = sum(len(sig) for sig in rsa_sigs) / len(rsa_sigs)

        ecdsa_sign_tps = self.iterations / ecdsa_sign_time if ecdsa_sign_time > 0 else 0
        rsa_sign_tps = self.iterations / rsa_sign_time if rsa_sign_time > 0 else 0
        ecdsa_verify_tps = (
            self.iterations / ecdsa_verify_time if ecdsa_verify_time > 0 else 0
        )
        rsa_verify_tps = self.iterations / rsa_verify_time if rsa_verify_time > 0 else 0

        # determine which is faster
        sign_ratio = max(ecdsa_sign_tps, rsa_sign_tps) / min(
            ecdsa_sign_tps, rsa_sign_tps
        )
        sign_text = f"{'ECDSA' if ecdsa_sign_tps > rsa_sign_tps else 'RSA'} is {sign_ratio:.1f}x faster for signing"

        verify_ratio = max(ecdsa_verify_tps, rsa_verify_tps) / min(
            ecdsa_verify_tps, rsa_verify_tps
        )
        verify_text = f"{'ECDSA' if ecdsa_verify_tps > rsa_verify_tps else 'RSA'} is {verify_ratio:.1f}x faster for verification"

        # update results display
        self.results_text.insert(
            "1.0",
            f"Key Size: ECDSA is {len(self.rsa_pubkey)/len(self.ecdsa_pubkey):.1f}x SMALLER ({len(self.ecdsa_pubkey)} bytes vs RSA's {len(self.rsa_pubkey)} bytes)\n"  # Removed \n
            f"Signature Size: ECDSA is {rsa_sig_size/ecdsa_sig_size:.1f}x SMALLER ({ecdsa_sig_size:.1f} bytes vs RSA's {rsa_sig_size:.1f} bytes)\n"  # Removed \n
            f"Signing Speed: {'ECDSA' if ecdsa_sign_tps > rsa_sign_tps else 'RSA'} is {sign_ratio:.1f}x FASTER\n"
            f"Verification: {'ECDSA' if ecdsa_verify_tps > rsa_verify_tps else 'RSA'} is {verify_ratio:.1f}x FASTER\n",
        )

        self.update_charts(
            ecdsa_sig_size,
            rsa_sig_size,
            ecdsa_sign_tps,
            rsa_sign_tps,
            ecdsa_verify_tps,
            rsa_verify_tps,
        )

        self.run_btn.config(state="normal")
        self.progress_var.set("Benchmark completed")

    def benchmark_ecdsa_signing(self, data):
        signatures = []
        start_time = time.time()
        for item in data:
            # ecdsa signing
            sig = self.ecdsa_private_key.sign(item, ec.ECDSA(hashes.SHA256()))
            signatures.append(sig)
        elapsed_time = time.time() - start_time
        return signatures, elapsed_time

    def benchmark_rsa_signing(self, data):
        signatures = []
        start_time = time.time()
        for item in data:
            # rsa signing
            sig = self.rsa_private_key.sign(
                item,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            signatures.append(sig)
        elapsed_time = time.time() - start_time
        return signatures, elapsed_time

    def benchmark_verification(self, data, ecdsa_sigs, rsa_sigs):
        # ecdsa verification benchmark
        start_time = time.time()
        for i in range(len(data)):
            # ecdsa verification
            self.ecdsa_public_key.verify(
                ecdsa_sigs[i], data[i], ec.ECDSA(hashes.SHA256())
            )
        ecdsa_time = time.time() - start_time

        # rsa verification benchmark
        start_time = time.time()
        for i in range(len(data)):
            # rsa verification
            self.rsa_public_key.verify(
                rsa_sigs[i],
                data[i],
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        rsa_time = time.time() - start_time

        return ecdsa_time, rsa_time

    def update_charts(
        self,
        ecdsa_sig_size,
        rsa_sig_size,
        ecdsa_sign_tps,
        rsa_sign_tps,
        ecdsa_verify_tps,
        rsa_verify_tps,
    ):
        for ax in self.ax.flat:
            ax.clear()

        colors = ["#2E86C1", "#E74C3C"]  # blue for ECDSA, red for RSA

        # key sizes
        key_sizes = [len(self.ecdsa_pubkey), len(self.rsa_pubkey)]
        bars = self.ax[0, 0].bar(["ECDSA", "RSA"], key_sizes, color=colors)
        self.ax[0, 0].set_title("Public Key Size (bytes)", fontsize=16)
        self.ax[0, 0].set_ylabel("Bytes", fontsize=14)
        for bar in bars:
            self.ax[0, 0].text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() * 1.02,
                f"{int(bar.get_height())}",
                ha="center",
                fontsize=14,
            )

        # signature sizes
        sig_sizes = [ecdsa_sig_size, rsa_sig_size]
        bars = self.ax[0, 1].bar(["ECDSA", "RSA"], sig_sizes, color=colors)
        self.ax[0, 1].set_title("Signature Size (bytes)", fontsize=16)
        self.ax[0, 1].set_ylabel("Bytes", fontsize=14)
        for bar in bars:
            self.ax[0, 1].text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() * 1.02,
                f"{int(bar.get_height())}",
                ha="center",
            )

        # signing speeds
        speeds = [ecdsa_sign_tps, rsa_sign_tps]
        bars = self.ax[1, 0].bar(["ECDSA", "RSA"], speeds, color=colors)
        self.ax[1, 0].set_title("Signing Speed (tx/sec)", fontsize=16)
        self.ax[1, 0].set_ylabel("TX/sec", fontsize=14)
        for bar in bars:
            self.ax[1, 0].text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() * 1.02,
                f"{int(bar.get_height())}",
                ha="center",
            )

        # verification speeds
        verify_speeds = [ecdsa_verify_tps, rsa_verify_tps]
        bars = self.ax[1, 1].bar(["ECDSA", "RSA"], verify_speeds, color=colors)
        self.ax[1, 1].set_title("Verification Speed (tx/sec)", fontsize=16)
        self.ax[1, 1].set_ylabel("TX/sec", fontsize=14)
        for bar in bars:
            self.ax[1, 1].text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() * 1.02,
                f"{int(bar.get_height())}",
                ha="center",
            )

        self.fig.tight_layout()
        self.canvas.draw()

    def cleanup(self):
        plt.close("all")  # Close all matplotlib figures
        self.root.destroy()  # Destroy the tkinter window


if __name__ == "__main__":
    root = tk.Tk()
    app = ECDSAvsRSADemo(root)
    root.protocol("WM_DELETE_WINDOW", app.cleanup)  # Bind cleanup to window close
    root.mainloop()
