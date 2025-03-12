import os
import time
import tkinter as tk
from tkinter import ttk
from cryptography.hazmat.primitives.asymmetric import ec, dsa
from cryptography.hazmat.primitives import hashes, serialization

class ECDSAvsDSADemo:
    def __init__(self, root):
        self.root = root
        root.title("ECDSA vs DSA for Bitcoin")
        root.geometry("750x600")
        
        # style for time text
        style = ttk.Style()
        style.configure("Time.TEntry", foreground="#bb0000", font=("Arial", 10, "bold"))        
        
        # main frame
        main_frame = ttk.Frame(root, padding=10)
        main_frame.pack(fill="both", expand=True)
        ttk.Label(main_frame, text="Bitcoin Digital Signatures: ECDSA vs Traditional DSA", 
                 font=("Arial", 14, "bold")).pack(pady=10)
        
        # transaction hash frame
        hash_frame = ttk.LabelFrame(main_frame, text="Transaction Hash (SigHash)", padding=10)
        hash_frame.pack(fill="x", pady=5)        
        hash_display = ttk.Frame(hash_frame)
        hash_display.pack(fill="x", pady=5)
        
        # random 32-byte hash to simulate a sighash
        self.current_hash = os.urandom(32)
        
        ttk.Label(hash_display, text="Hash:").grid(column=0, row=0, sticky="w", padx=(0,5))
        self.hash_var = tk.StringVar(value=self.current_hash.hex())
        hash_entry = ttk.Entry(hash_display, textvariable=self.hash_var, width=85)
        hash_entry.grid(column=1, row=0, sticky="w", padx=(0,5))
        hash_entry.config(state="readonly")
        
        ttk.Button(hash_display, text="New Hash", 
                  command=self.generate_new_hash).grid(column=2, row=0, padx=5)
        
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill="x", pady=10)
        
        # iterations to simulate multiple operations
        self.iterations = 1000
        
        ttk.Button(action_frame, text=f"Sign ({self.iterations} tx)", 
                  command=self.sign_hash).pack(side="left", padx=5)
        ttk.Button(action_frame, text=f"Verify ({self.iterations} tx)", 
                  command=self.verify_signatures).pack(side="left", padx=5)
        
        explanation = ttk.Label(action_frame, 
            text=(
                "What this simulates:\n"
                f"• Sign: Creating {self.iterations} signatures (like signing transactions)\n"
                f"• Verify: Like checking a block of {self.iterations} transactions\n"
                "  (A typical Bitcoin block has 2000-3000 transactions)"
            ),
            justify="left",
            font=("Arial", 9)
        )
        explanation.pack(side="left", padx=10)
        
        # ECDSA frame 
        ecdsa_frame = ttk.LabelFrame(main_frame, text="ECDSA", padding=10)
        ecdsa_frame.pack(fill="x", pady=5)
        
        # ECDSA key info
        ttk.Label(ecdsa_frame, text="Private Key Size:").grid(column=0, row=0, sticky="w")
        ttk.Label(ecdsa_frame, text="32 bytes (256 bits)").grid(column=1, row=0, sticky="w")
        
        ttk.Label(ecdsa_frame, text="Public Key (compressed):").grid(column=0, row=1, sticky="w", pady=2)
        self.ecdsa_pubkey_size_var = tk.StringVar(value="33 bytes (used by Bitcoin)")
        ttk.Entry(ecdsa_frame, textvariable=self.ecdsa_pubkey_size_var, 
                 width=40, state="readonly").grid(column=1, row=1, sticky="w")
        
        ttk.Label(ecdsa_frame, text="Public Key:").grid(column=0, row=2, sticky="nw", pady=2)
        self.ecdsa_pubkey_text = tk.Text(ecdsa_frame, height=2, width=90, wrap="word")
        self.ecdsa_pubkey_text.grid(column=1, row=2, sticky="w")
        self.ecdsa_pubkey_text.config(state="disabled")
        
        ttk.Label(ecdsa_frame, text="Signature:").grid(column=0, row=3, sticky="nw", pady=2)
        self.ecdsa_sig_text = tk.Text(ecdsa_frame, height=1, width=80, wrap="word")
        self.ecdsa_sig_text.grid(column=1, row=3, sticky="w")
        self.ecdsa_sig_text.config(state="disabled")
        
        ttk.Label(ecdsa_frame, text="Time:").grid(column=0, row=4, sticky="w", pady=2)
        self.ecdsa_time_var = tk.StringVar(value="N/A")
        ttk.Entry(ecdsa_frame, textvariable=self.ecdsa_time_var, 
                 width=40, style="Time.TEntry").grid(column=1, row=4, sticky="w")
        
        # DSA frame
        dsa_frame = ttk.LabelFrame(main_frame, text="DSA (Traditional)", padding=10)
        dsa_frame.pack(fill="x", pady=5)
        
        ttk.Label(dsa_frame, text="Private Key Size:").grid(column=0, row=0, sticky="w")
        ttk.Label(dsa_frame, text="384 bytes (3072 bits)").grid(column=1, row=0, sticky="w")
        
        ttk.Label(dsa_frame, text="Public Key Size:").grid(column=0, row=1, sticky="w", pady=2)
        self.dsa_pubkey_size_var = tk.StringVar(value="~1200-1300 bytes (no compression possible)")
        
        ttk.Entry(dsa_frame, textvariable=self.dsa_pubkey_size_var, 
                 width=40, state="readonly").grid(column=1, row=1, sticky="w")
        
        ttk.Label(dsa_frame, text="Public Key:").grid(column=0, row=2, sticky="nw", pady=2)
        self.dsa_pubkey_text = tk.Text(dsa_frame, height=4, width=90, wrap="word")
        self.dsa_pubkey_text.grid(column=1, row=2, sticky="w")
        self.dsa_pubkey_text.config(state="disabled")
        
        ttk.Label(dsa_frame, text="Signature:").grid(column=0, row=3, sticky="nw", pady=2)
        self.dsa_sig_text = tk.Text(dsa_frame, height=1, width=80, wrap="word")
        self.dsa_sig_text.grid(column=1, row=3, sticky="w")
        self.dsa_sig_text.config(state="disabled")
        
        ttk.Label(dsa_frame, text="Time:").grid(column=0, row=4, sticky="w", pady=2)
        self.dsa_time_var = tk.StringVar(value="N/A")
        ttk.Entry(dsa_frame, textvariable=self.dsa_time_var, 
                 width=40, style="Time.TEntry").grid(column=1, row=4, sticky="w")
        
        # results frame
        result_frame = ttk.LabelFrame(main_frame, text="Results", padding=10)
        result_frame.pack(fill="x", pady=5)
        self.result_text = tk.Text(result_frame, height=7, width=60, wrap="word", font=("Arial", 9))
        self.result_text.pack(fill="both")
        self.result_text.insert("1.0", "Click 'Sign' to start comparison")
        self.result_text.config(state="disabled")
        
        # generate initial keys
        self.generate_keys()
    
    def update_text_widget(self, widget, text):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.config(state="disabled")
    
    def generate_keys(self):
        # generate ECDSA keys (using SECP256K1 curve like Bitcoin)
        self.ecdsa_private_key = ec.generate_private_key(ec.SECP256K1())
        self.ecdsa_public_key = self.ecdsa_private_key.public_key()
        
        # generate DSA keys - use 3072 bits for comparison
        self.dsa_private_key = dsa.generate_private_key(key_size=3072)
        self.dsa_public_key = self.dsa_private_key.public_key()
        
        # reset signatures
        self.ecdsa_signature = None
        self.dsa_signature = None
        
        # get public key values 
        compressed_pubkey = self.ecdsa_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )
        
        # update ECDSA public key text
        self.update_text_widget(
            self.ecdsa_pubkey_text, 
            f"Compressed ({len(compressed_pubkey)} bytes): {compressed_pubkey.hex()[:50]}..."
        )
        
        # get DSA public key for display 
        try:
            dsa_pub_bytes = self.dsa_public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            dsa_hex = dsa_pub_bytes.hex()
            displayed_hex = dsa_hex[:200] + "...\n" + dsa_hex[200:400] + "...\n" + dsa_hex[400:500]
            
            self.update_text_widget(
                self.dsa_pubkey_text,
                f"DSA Public Key ({len(dsa_pub_bytes)} bytes):\n{displayed_hex}..."
            )
        except Exception as e:
            self.update_text_widget(
                self.dsa_pubkey_text,
                f"Error displaying key: {str(e)}"
            )
        
        # pre-warm the libraries because first signature is slow
        temp_hash = os.urandom(32)
        for _ in range(3):
            self.ecdsa_private_key.sign(temp_hash, ec.ECDSA(hashes.SHA256()))
            self.dsa_private_key.sign(temp_hash, hashes.SHA256())
    
    def generate_new_hash(self):
        self.current_hash = os.urandom(32)
        self.hash_var.set(self.current_hash.hex())
        
        # resets 
        self.ecdsa_signature = None
        self.dsa_signature = None
        self.update_text_widget(self.ecdsa_sig_text, "Not signed yet")
        self.update_text_widget(self.dsa_sig_text, "Not signed yet")
        self.ecdsa_time_var.set("N/A")
        self.dsa_time_var.set("N/A")
        self.update_text_widget(self.result_text, "Click 'Sign' to start comparison")
    
    def sign_hash(self):
        # ECDSA signing
        start_time = time.time()
        for _ in range(self.iterations):
            self.ecdsa_signature = self.ecdsa_private_key.sign(
                self.current_hash,
                ec.ECDSA(hashes.SHA256())
            )
        ecdsa_time = time.time() - start_time
        
        # get compressed public key
        compressed_pubkey = self.ecdsa_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )
        
        self.update_text_widget(
            self.ecdsa_pubkey_text, 
            f"Compressed ({len(compressed_pubkey)} bytes): {compressed_pubkey.hex()}"
        )
        self.update_text_widget(
            self.ecdsa_sig_text,
            f"{len(self.ecdsa_signature)} bytes: {self.ecdsa_signature.hex()[:50]}..."
        )
        
        # calculate transactions per second
        ecdsa_tps = int(self.iterations / ecdsa_time) if ecdsa_time > 0 else 0
        self.ecdsa_time_var.set(f"{ecdsa_time:.3f} sec | ~{ecdsa_tps} tx/sec")
        
        # DSA signing
        start_time = time.time()
        for _ in range(self.iterations):
            self.dsa_signature = self.dsa_private_key.sign(
                self.current_hash,
                hashes.SHA256()
            )
        dsa_time = time.time() - start_time
        
        try:
            dsa_pub_bytes = self.dsa_public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            dsa_pubkey_size = len(dsa_pub_bytes)
            
            dsa_hex = dsa_pub_bytes.hex()
            displayed_hex = dsa_hex[:200] + "...\n" + dsa_hex[200:400] + "...\n" + dsa_hex[400:500]
            
            self.update_text_widget(
                self.dsa_pubkey_text,
                f"DSA Public Key ({dsa_pubkey_size} bytes):\n{displayed_hex}..."
            )
        except Exception as e:
            dsa_pubkey_size = 384 
            self.update_text_widget(
                self.dsa_pubkey_text,
                f"Error displaying full key: {str(e)}"
            )
        
        self.update_text_widget(
            self.dsa_sig_text,
            f"{len(self.dsa_signature)} bytes: {self.dsa_signature.hex()[:50]}..."
        )
        
        # calculate and display stats
        dsa_tps = int(self.iterations / dsa_time) if dsa_time > 0 else 0
        self.dsa_time_var.set(f"{dsa_time:.3f} sec | ~{dsa_tps} tx/sec")
        key_ratio = dsa_pubkey_size / len(compressed_pubkey)
        sig_ratio = len(self.dsa_signature) / len(self.ecdsa_signature)
        time_ratio = dsa_time / ecdsa_time if ecdsa_time > 0 else 1
        key_space_saved = 1000 * (dsa_pubkey_size - len(compressed_pubkey))  # bytes saved
        key_space_saved_kb = key_space_saved / 1024  # convert to KB
        time_saved = 1000 * (dsa_time - ecdsa_time) / self.iterations  # seconds saved for 1000 transactions
        
        results = (
            f"Key Size: ECDSA {len(compressed_pubkey)} bytes vs DSA ~{dsa_pubkey_size} bytes ({key_ratio:.1f}x larger)\n"
            f"Signature: ECDSA {len(self.ecdsa_signature)} bytes vs DSA {len(self.dsa_signature)} bytes\n"
            f"Speed: ECDSA {ecdsa_tps} tx/sec vs DSA {dsa_tps} tx/sec ({time_ratio:.1f}x slower)\n\n"
            f"FOR 1000 TRANSACTIONS:\n"
            f"Space Saved from Keys: {key_space_saved_kb:.1f} KB\n"
            f"Time Saved: {time_saved:.2f} seconds\n\n"
            f"Bitcoin chose ECDSA for smaller keys ({len(compressed_pubkey)} vs {dsa_pubkey_size} bytes), "
            f"faster operations, and equivalent security strength."
        )
        self.update_text_widget(self.result_text, results)
    
    def verify_signatures(self):
        """Verify both signatures multiple times"""
        if not self.ecdsa_signature or not self.dsa_signature:
            self.update_text_widget(self.result_text, "Please sign the hash first before verifying")
            return
            
        # ECDSA verification
        try:
            start_time = time.time()
            for _ in range(self.iterations):
                self.ecdsa_public_key.verify(
                    self.ecdsa_signature,
                    self.current_hash,
                    ec.ECDSA(hashes.SHA256())
                )
            ecdsa_time = time.time() - start_time
            ecdsa_valid = True
        except Exception:
            ecdsa_valid = False
            ecdsa_time = 0
        
        # DSA verification
        try:
            start_time = time.time()
            for _ in range(self.iterations):
                self.dsa_public_key.verify(
                    self.dsa_signature,
                    self.current_hash,
                    hashes.SHA256()
                )
            dsa_time = time.time() - start_time
            dsa_valid = True
        except Exception:
            dsa_valid = False
            dsa_time = 0
        
        if ecdsa_valid and dsa_valid:
             
            # calculate and display stats
            ecdsa_tps = int(self.iterations / ecdsa_time) if ecdsa_time > 0 else 0
            dsa_tps = int(self.iterations / dsa_time) if dsa_time > 0 else 0
            self.ecdsa_time_var.set(f"{ecdsa_time:.3f} sec | ~{ecdsa_tps} tx/sec")
            self.dsa_time_var.set(f"{dsa_time:.3f} sec | ~{dsa_tps} tx/sec")
            time_ratio = dsa_time / ecdsa_time if ecdsa_time > 0 else 1
            time_saved = 1000 * (dsa_time - ecdsa_time) / self.iterations  # seconds saved for 1000 transactions
            
            results = (
                f"Verification successful for both algorithms\n"
                f"Speed: ECDSA {ecdsa_tps} tx/sec vs DSA {dsa_tps} tx/sec ({time_ratio:.1f}x slower)\n\n"
                f"FOR 1000 TRANSACTIONS:\n"
                f"Time Saved during Verification: {time_saved:.2f} seconds\n\n"
                f"This is why Bitcoin can validate blocks much faster with ECDSA!"
            )
            self.update_text_widget(self.result_text, results)
        else:
            msg = "Verification failed: "
            if not ecdsa_valid:
                msg += "ECDSA failed. "
            if not dsa_valid:
                msg += "DSA failed."
            self.update_text_widget(self.result_text, msg)

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = ECDSAvsDSADemo(root)
        root.mainloop()
    except Exception as e:
        import traceback
        print(f"Error: {e}")
        traceback.print_exc()