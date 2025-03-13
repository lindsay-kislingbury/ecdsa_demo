import os
import time
import tkinter as tk
from tkinter import ttk, scrolledtext
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

class ECDSAvsRSADemo:
    def __init__(self, root):
        self.root = root
        root.title("ECDSA vs RSA")
        root.geometry("800x600")
        
        # main container
        main_frame = ttk.Frame(root, padding=5)
        main_frame.pack(fill="both", expand=True)
        ttk.Label(main_frame, text="ECDSA vs RSA Comparison").pack(pady=5)
        
        # transaction hash frame
        hash_frame = ttk.Frame(main_frame)
        hash_frame.pack(fill="x", pady=2)
        
        self.current_hash = os.urandom(32)
        self.hash_var = tk.StringVar(value=self.current_hash.hex())
        
        ttk.Label(hash_frame, text="Hash:").pack(side="left")
        hash_entry = ttk.Entry(hash_frame, textvariable=self.hash_var, width=80)
        hash_entry.pack(side="left", padx=5)
        hash_entry.config(state="readonly")
        
        ttk.Button(hash_frame, text="New Hash", 
                  command=self.generate_new_hash).pack(side="left")
        
        # action Buttons
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill="x", pady=5)
        
        self.iterations = 100
        ttk.Button(action_frame, text=f"Sign ({self.iterations} tx)", 
                  command=self.sign_hash).pack(side="left", padx=5)
        
        # ECDSA section
        ecdsa_frame = ttk.LabelFrame(main_frame, text="ECDSA (256-bit)", padding=5)
        ecdsa_frame.pack(fill="x", pady=2)
        
        ttk.Label(ecdsa_frame, text="Keys:").pack(anchor="w")
        self.ecdsa_key_text = scrolledtext.ScrolledText(ecdsa_frame, height=4, width=90, wrap="word")
        self.ecdsa_key_text.pack(fill="x", pady=2)
        
        ttk.Label(ecdsa_frame, text="Signature:").pack(anchor="w")
        self.ecdsa_sig_text = scrolledtext.ScrolledText(ecdsa_frame, height=3, width=90, wrap="word")
        self.ecdsa_sig_text.pack(fill="x", pady=2)
        
        ttk.Label(ecdsa_frame, text="Time:").pack(side="left")
        self.ecdsa_time_var = tk.StringVar(value="N/A")
        ttk.Label(ecdsa_frame, textvariable=self.ecdsa_time_var).pack(side="left", padx=5)
        
        # RSA section
        rsa_frame = ttk.LabelFrame(main_frame, text="RSA (3072-bit)", padding=5)
        rsa_frame.pack(fill="x", pady=2)
        
        ttk.Label(rsa_frame, text="Keys:").pack(anchor="w")
        self.rsa_key_text = scrolledtext.ScrolledText(rsa_frame, height=6, width=90, wrap="word")
        self.rsa_key_text.pack(fill="x", pady=2)
        
        ttk.Label(rsa_frame, text="Signature:").pack(anchor="w")
        self.rsa_sig_text = scrolledtext.ScrolledText(rsa_frame, height=5, width=90, wrap="word")
        self.rsa_sig_text.pack(fill="x", pady=2)
        
        ttk.Label(rsa_frame, text="Time:").pack(side="left")
        self.rsa_time_var = tk.StringVar(value="N/A")
        ttk.Label(rsa_frame, textvariable=self.rsa_time_var).pack(side="left", padx=5)
        
        # results section
        result_frame = ttk.LabelFrame(main_frame, text="Results", padding=5)
        result_frame.pack(fill="x", pady=2)
        self.result_text = scrolledtext.ScrolledText(result_frame, height=3, width=90, wrap="word")
        self.result_text.pack(fill="both")
        self.result_text.insert("1.0", "Click 'Sign' to compare ECDSA vs RSA")
        
        # generate initial keys
        self.generate_keys()
    
    def generate_keys(self):
        # generate ECDSA keys (using SECP256K1 curve like Bitcoin)
        self.ecdsa_private_key = ec.generate_private_key(ec.SECP256K1())
        self.ecdsa_public_key = self.ecdsa_private_key.public_key()
        
        # generate RSA keys with 3072 bits for equivalent security to 256-bit ECC
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072
        )
        self.rsa_public_key = self.rsa_private_key.public_key()
        
        self.ecdsa_signature = None
        self.rsa_signature = None
        
        # display ECDSA keys
        try:
            ecdsa_private_bytes = self.ecdsa_private_key.private_numbers().private_value.to_bytes(32, byteorder='big')
            
            compressed_pubkey = self.ecdsa_public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.CompressedPoint
            )
            
            self.ecdsa_key_text.delete("1.0", "end")
            self.ecdsa_key_text.insert("1.0", 
                f"Private key ({len(ecdsa_private_bytes)} bytes): {ecdsa_private_bytes.hex()}\n"
                f"Public key (compressed, {len(compressed_pubkey)} bytes): {compressed_pubkey.hex()}"
            )
        except Exception as e:
            self.ecdsa_key_text.delete("1.0", "end")
            self.ecdsa_key_text.insert("1.0", f"Error: {str(e)}")
        
        # display RSA keys
        try:
            rsa_pub_bytes = self.rsa_public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            self.rsa_key_text.delete("1.0", "end")
            self.rsa_key_text.insert("1.0", 
                f"RSA key size: 3072 bits\n"
                f"Public key ({len(rsa_pub_bytes)} bytes): {rsa_pub_bytes.hex()}"
            )
        except Exception as e:
            self.rsa_key_text.delete("1.0", "end")
            self.rsa_key_text.insert("1.0", f"Error: {str(e)}")
        
        # pre-warm libraries
        temp_hash = os.urandom(32)
        for _ in range(3):
            self.ecdsa_private_key.sign(temp_hash, ec.ECDSA(hashes.SHA256()))
            self.rsa_private_key.sign(
                temp_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        
        self.ecdsa_sig_text.delete("1.0", "end")
        self.ecdsa_sig_text.insert("1.0", "Not signed yet")
        self.rsa_sig_text.delete("1.0", "end")
        self.rsa_sig_text.insert("1.0", "Not signed yet")
    
    def generate_new_hash(self):
        self.current_hash = os.urandom(32)
        self.hash_var.set(self.current_hash.hex())
        
        self.ecdsa_signature = None
        self.rsa_signature = None
        self.ecdsa_sig_text.delete("1.0", "end")
        self.ecdsa_sig_text.insert("1.0", "Not signed yet")
        self.rsa_sig_text.delete("1.0", "end")
        self.rsa_sig_text.insert("1.0", "Not signed yet")
        self.ecdsa_time_var.set("N/A")
        self.rsa_time_var.set("N/A")
        self.result_text.delete("1.0", "end")
        self.result_text.insert("1.0", "Click 'Sign' to compare ECDSA vs RSA")
    
    def sign_hash(self):
        # ECDSA signing
        start_time = time.time()
        for _ in range(self.iterations):
            self.ecdsa_signature = self.ecdsa_private_key.sign(
                self.current_hash,
                ec.ECDSA(hashes.SHA256())
            )
        ecdsa_time = time.time() - start_time
        
        self.ecdsa_sig_text.delete("1.0", "end")
        self.ecdsa_sig_text.insert("1.0", 
            f"{len(self.ecdsa_signature)} bytes: {self.ecdsa_signature.hex()}"
        )
        
        # calculate transactions per second
        ecdsa_tps = int(self.iterations / ecdsa_time) if ecdsa_time > 0 else 0
        self.ecdsa_time_var.set(f"{ecdsa_time:.3f} sec | ~{ecdsa_tps} tx/sec")
        
        # RSA signing
        start_time = time.time()
        for _ in range(self.iterations):
            self.rsa_signature = self.rsa_private_key.sign(
                self.current_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        rsa_time = time.time() - start_time
        
        self.rsa_sig_text.delete("1.0", "end")
        self.rsa_sig_text.insert("1.0", 
            f"{len(self.rsa_signature)} bytes: {self.rsa_signature.hex()}"
        )
        
        # calculate and display stats
        rsa_tps = int(self.iterations / rsa_time) if rsa_time > 0 else 0
        self.rsa_time_var.set(f"{rsa_time:.3f} sec | ~{rsa_tps} tx/sec")
        
        compressed_pubkey = self.ecdsa_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )
        
        rsa_pub_bytes = self.rsa_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        rsa_pubkey_size = len(rsa_pub_bytes)
        
        key_ratio = rsa_pubkey_size / len(compressed_pubkey)
        sig_ratio = len(self.rsa_signature) / len(self.ecdsa_signature)
        time_ratio = rsa_time / ecdsa_time if ecdsa_time > 0 else 1
        
        self.result_text.delete("1.0", "end")
        self.result_text.insert("1.0", 
            f"Key: ECDSA {len(compressed_pubkey)} vs RSA {rsa_pubkey_size} bytes (RSA is {key_ratio:.1f}x larger)\n"
            f"Signature: ECDSA {len(self.ecdsa_signature)} vs RSA {len(self.rsa_signature)} bytes (RSA is {sig_ratio:.1f}x larger)\n"
            f"Signing: ECDSA {ecdsa_tps} tx/sec vs RSA {rsa_tps} tx/sec (RSA is {time_ratio:.1f}x slower)"
        )

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = ECDSAvsRSADemo(root)
        root.mainloop()
    except Exception as e:
        import traceback
        print(f"Error: {e}")
        traceback.print_exc()