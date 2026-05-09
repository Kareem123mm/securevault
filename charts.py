import json
import os
import matplotlib.pyplot as plt

def load_json(path):
   """Helper function to load a JSON file from a given path."""
   try:
       with open(path) as f:
           return json.load(f)
   except FileNotFoundError:
       print(f"Error: Benchmark file not found at {path}.")
       print("Please run the corresponding performance benchmark script first.")
       exit()

def make_charts():
   """
   Generates and saves four performance charts based on the benchmark JSON files.
   """
   os.makedirs("performance_results", exist_ok=True)
   
   # Load data from all benchmark runs
   a = load_json("performance_results/module_a_bench.json")
   b = load_json("performance_results/module_b_bench.json")
   full = load_json("performance_results/full_bench.json")
   labels = ["1KB", "10KB", "100KB"]
   
   # --- CHART 1: Symmetric Cipher Runtime Comparison ---
   rc6_enc  = [a["rc6"][l]["encrypt"]["avg_ms"]  for l in labels]
   xtea_enc = [a["xtea"][l]["encrypt"]["avg_ms"] for l in labels]
   
   fig, ax = plt.subplots(figsize=(8, 5))
   ax.plot(labels, rc6_enc,  'b-o', label='RC6',  linewidth=2, markersize=8)
   ax.plot(labels, xtea_enc, 'r--s', label='XTEA', linewidth=2, markersize=8)
   ax.set_title("RC6 vs XTEA Encryption Time", fontsize=14, fontweight='bold')
   ax.set_xlabel("File Size")
   ax.set_ylabel("Time (ms)")
   ax.legend()
   ax.grid(True, which='both', linestyle='--', linewidth=0.5)
   # Annotate data points
   for x, y in zip(labels, rc6_enc):
       ax.annotate(f"{y:.2f}", (x, y), textcoords="offset points", xytext=(0, 10), ha='center', fontsize=9)
   for x, y in zip(labels, xtea_enc):
       ax.annotate(f"{y:.2f}", (x, y), textcoords="offset points", xytext=(0, -15), ha='center', fontsize=9)
   plt.tight_layout()
   plt.savefig("performance_results/chart_runtime.png", dpi=150)
   plt.close()
   print("Saved chart_runtime.png")
   
   # --- CHART 2: Symmetric Cipher Memory Usage ---
   rc6_mem  = [a["rc6"][l]["encrypt"]["peak_memory_kb"]  for l in labels]
   xtea_mem = [a["xtea"][l]["encrypt"]["peak_memory_kb"] for l in labels]
   x_pos = range(len(labels))
   
   fig, ax = plt.subplots(figsize=(8, 5))
   width = 0.35
   bars1 = ax.bar([p - width/2 for p in x_pos], rc6_mem,  width, label='RC6',  color='steelblue')
   bars2 = ax.bar([p + width/2 for p in x_pos], xtea_mem, width, label='XTEA', color='tomato')
   ax.set_title("Peak Memory Usage During Encryption", fontsize=14, fontweight='bold')
   ax.set_xlabel("File Size")
   ax.set_ylabel("Peak Memory (KB)")
   ax.set_xticks(list(x_pos))
   ax.set_xticklabels(labels)
   ax.legend()
   ax.grid(True, axis='y', linestyle='--', linewidth=0.5)
   # Annotate bars
   for bar in bars1:
       ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.2,
               f"{bar.get_height():.1f}", ha='center', va='bottom', fontsize=8)
   for bar in bars2:
       ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.2,
               f"{bar.get_height():.1f}", ha='center', va='bottom', fontsize=8)
   plt.tight_layout()
   plt.savefig("performance_results/chart_memory.png", dpi=150)
   plt.close()
   print("Saved chart_memory.png")
   
   # --- CHART 3: Ciphertext Expansion Ratio ---
   rc6_ratio  = a["rc6"]["1KB"]["encrypt"]["expansion_ratio"]
   xtea_ratio = a["xtea"]["1KB"]["encrypt"]["expansion_ratio"]
   # ElGamal ratio is calculated as total bits for two components vs. 128-bit block
   elg_ratio  = full["overhead"]["elgamal_bits_per_block"] / 128.0
   
   names  = ["RC6", "XTEA", "ElGamal"]
   ratios = [rc6_ratio, xtea_ratio, elg_ratio]
   colors = ['#4CAF50', '#FFC107', '#F44336'] # Green, Amber, Red
   
   fig, ax = plt.subplots(figsize=(7, 5))
   bars = ax.bar(names, ratios, color=colors, edgecolor='black', linewidth=0.5)
   ax.axhline(y=1.0, color='black', linestyle='--', linewidth=1, label='Ideal (No Overhead)')
   ax.set_title("Ciphertext Expansion Ratio", fontsize=14, fontweight='bold')
   ax.set_ylabel("Ciphertext Size / Plaintext Size")
   ax.legend()
   ax.grid(True, axis='y', linestyle='--', linewidth=0.5)
   # Annotate bars
   for bar, ratio in zip(bars, ratios):
       ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
               f"{ratio:.3f}", ha='center', va='bottom', fontsize=10)
   plt.tight_layout()
   plt.savefig("performance_results/chart_ciphertext.png", dpi=150)
   plt.close()
   print("Saved chart_ciphertext.png")
   
   # --- CHART 4: ElGamal Operation Costs ---
   ops   = ["Keygen", "Encrypt", "Decrypt", "Sign", "Verify"]
   label_16b = "16B" # Use the 16-byte data point for comparison
   times_ms = [
       b["keygen"]["avg_ms"],
       b["operations"][label_16b]["encrypt"]["avg_ms"],
       b["operations"][label_16b]["decrypt"]["avg_ms"],
       b["operations"][label_16b]["sign"]["avg_ms"],
       b["operations"][label_16b]["verify"]["avg_ms"]
   ]
   
   fig, ax = plt.subplots(figsize=(8, 5))
   bars = ax.barh(ops, times_ms, color='mediumpurple', edgecolor='black', linewidth=0.5)
   ax.set_title("ElGamal Operation Costs", fontsize=14, fontweight='bold')
   ax.set_xlabel("Time (ms)")
   ax.invert_yaxis() # Show most expensive at the top
   ax.grid(True, axis='x', linestyle='--', linewidth=0.5)
   # Annotate horizontal bars
   for bar, val in zip(bars, times_ms):
       ax.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height() / 2,
               f"{val:.2f} ms", va='center', ha='left', fontsize=9)
   plt.tight_layout()
   plt.savefig("performance_results/chart_operations.png", dpi=150)
   plt.close()
   print("Saved chart_operations.png")

if __name__ == "__main__":
   make_charts()
   print("\nAll 4 charts saved to performance_results/")
