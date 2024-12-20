import matplotlib.pyplot as plt
import os

plt.rcParams.update({'font.size': 14})

# Data for Pairing-less KVAC
sizes = ['(16, 8)', '(64, 32)', '(256, 128)', '(1024, 512)', '(4096, 2048)']
# pairing_less = {
#     "IssueCred": [6.362, 23.199, 91.235, 357.377, 1701.912],
#     "ObtainCred": [8.250, 31.235, 127.350, 508.384, 2310.885],
#     "ShowCred": [1.551, 5.309, 20.740, 85.541, 408.335],
#     "VerifyCred": [0.279, 0.317, 0.629, 5.876, 88.481]
# }

pairing_less = {
    "IssueCred": [6.921, 21.752, 85.550, 340.791, 1354.058],
    "ObtainCred": [7.895, 30.377, 122.100, 512.565, 2354.835],
    "ShowCred": [1.617, 5.405, 20.636, 85.291, 402.898],
    "VerifyCred": [0.139, 0.151, 0.143, 0.144, 0.165],
}

# # Data for Pairing-based KVAC
# pairing_based = {
#     "IssueCred": [5.092, 13.102, 46.084, 190.168, 990.541],
#     "ObtainCred": [4.509, 12.073, 43.083, 182.621, 985.557],
#     "ShowCred": [2.614, 6.405, 21.555, 86.159, 407.319],
#     "VerifyCred": [2.397, 2.445, 2.788, 7.972, 89.706]
# }

pairing_based = {
    "IssueCred": [4.836, 12.644, 43.339, 184.877, 980.832],
    "ObtainCred": [4.686, 12.307, 43.826, 184.261, 981.722],
    "ShowCred": [2.693, 6.470, 21.882, 87.683, 408.177],
    "VerifyCred": [2.451, 2.476, 2.363, 2.369, 2.362],
}

# # Data for output sizes
# output_sizes_pairing_less = {
#     "IssueCred": [960, 3264, 12480, 49344, 196800],
#     "ObtainCred": [912, 3216, 12432, 49296, 196752],
#     "ShowCred": [96, 96, 96, 96, 96]  # In bytes
# }

output_sizes_pairing_less = {
    "IssueCred": [960, 3264, 12480, 49344, 196800],
    "ObtainCred": [912, 3216, 12432, 49296, 196752],
    "ShowCred": [96, 96, 96, 96, 96],  # In bytes
}

# output_sizes_pairing_based = {
#     "IssueCred": [272, 272, 272, 272, 272],
#     "ObtainCred": [240, 240, 240, 240, 240],
#     "ShowCred": [240, 240, 240, 240, 240]  # In bytes
# }

output_sizes_pairing_based = {
    "IssueCred": [272, 272, 272, 272, 272],
    "ObtainCred": [240, 240, 240, 240, 240],
    "ShowCred": [240, 240, 240, 240, 240],  # In bytes
}

# Convert to KB
output_sizes_pairing_less_kb = {
    "IssueCred": [x / 1024 for x in output_sizes_pairing_less["IssueCred"]],
    "ObtainCred": [x / 1024 for x in output_sizes_pairing_less["ObtainCred"]],
    "ShowCred": [x / 1024 for x in output_sizes_pairing_less["ShowCred"]]
}

output_sizes_pairing_based_kb = {
    "IssueCred": [x / 1024 for x in output_sizes_pairing_based["IssueCred"]],
    "ObtainCred": [x / 1024 for x in output_sizes_pairing_based["ObtainCred"]],
    "ShowCred": [x / 1024 for x in output_sizes_pairing_based["ShowCred"]]
}

# Save plots in the current folder
current_folder = "./"

# Save plots for each function
for function in pairing_less.keys():
    plt.figure(figsize=(10, 6))
    plt.plot(sizes, pairing_less[function], label="Pairingless KVAC", marker='o')
    plt.plot(sizes, pairing_based[function], label="Pairing-based KVAC", marker='o')
    plt.xlabel("Input Size (S_size, D_size)")
    plt.ylabel("Execution Time (ms)")
    plt.title(f"Execution Time Comparison for $\\mathbf{{{function}}}$")
    plt.yscale('log')  # Logarithmic scale for better visualization
    plt.legend()
    plt.grid(True)
    file_path = os.path.join(current_folder, f"{function}_execution_time_comparison.pdf")
    plt.savefig(file_path)  # Save the plot
    plt.close()

# Plot output sizes in KB for each function
for function in output_sizes_pairing_less_kb.keys():
    plt.figure(figsize=(10, 6))
    plt.plot(sizes, output_sizes_pairing_less_kb[function], label="Pairingless KVAC", marker='o')
    plt.plot(sizes, output_sizes_pairing_based_kb[function], label="Pairing-based KVAC", marker='o')
    plt.xlabel("Input Size (S_size, D_size)")
    plt.ylabel("Output Size (KB)")
    plt.title(f"Output Size Comparison for $\\mathbf{{{function}}}$ (in KB)")
    plt.legend()
    plt.grid(True)
    file_path = os.path.join(current_folder, f"{function}_output_size_comparison_kb.pdf")
    plt.savefig(file_path)  # Save the plot
    plt.close()

current_folder
