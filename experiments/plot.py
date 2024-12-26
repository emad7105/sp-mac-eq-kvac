import matplotlib.pyplot as plt
import os

plt.rcParams.update({'font.size': 14})

# Data for Pairing-less KVAC
sizes = ['(16, 8)', '(64, 32)', '(256, 128)', '(1024, 512)', '(4096, 2048)']

pairing_less = {
    "IssueCred": [6.143, 21.741, 85.716, 337.586, 1357.423],
    "ObtainCred": [8.335, 31.903, 128.270, 531.214, 2366.743],
    "ShowCred": [1.607, 5.479, 20.844, 87.501, 411.198],
    "VerifyCred": [0.152, 0.142, 0.154, 0.160, 0.172],
}

pairing_based = {
    "IssueCred": [4.836, 12.528, 44.581, 186.216, 991.882],
    "ObtainCred": [4.695, 12.383, 44.524, 187.648, 992.525],
    "ShowCred": [2.362, 6.311, 21.872, 88.384, 412.398],
    "VerifyCred": [2.458, 2.419, 2.442, 2.464, 2.514],
}

output_sizes_pairing_less = {
    "IssueCred": [960, 3264, 12480, 49344, 196800],
    "ObtainCred": [864, 3168, 12384, 49248, 196704],
    "ShowCred": [96, 96, 96, 96, 96],  # In bytes
}

# output_sizes_pairing_based = {
#     "IssueCred": [272, 272, 272, 272, 272],
#     "ObtainCred": [240, 240, 240, 240, 240],
#     "ShowCred": [240, 240, 240, 240, 240]  # In bytes
# }

# output_sizes_pairing_based = {
#     "IssueCred": [272, 272, 272, 272, 272],
#     "ObtainCred": [240, 240, 240, 240, 240],
#     "ShowCred": [240, 240, 240, 240, 240],  # In bytes
# }

output_sizes_pairing_based = {
    "IssueCred": [272, 272, 272, 272, 272],
    "ObtainCred": [144, 144, 144, 144, 144],
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
