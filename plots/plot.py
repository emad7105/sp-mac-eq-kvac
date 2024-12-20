import matplotlib.pyplot as plt
import os

# Data for Pairing-less KVAC
sizes = ['(16, 8)', '(64, 32)', '(256, 128)', '(1024, 512)', '(4096, 2048)']
pairing_less = {
    "Issue_cred": [6.362, 23.199, 91.235, 357.377, 1701.912],
    "Obtain_cred": [8.250, 31.235, 127.350, 508.384, 2310.885],
    "Show_cred": [1.551, 5.309, 20.740, 85.541, 408.335],
    "Verify_cred": [0.279, 0.317, 0.629, 5.876, 88.481]
}

# Data for Pairing-based KVAC
pairing_based = {
    "Issue_cred": [5.092, 13.102, 46.084, 190.168, 990.541],
    "Obtain_cred": [4.509, 12.073, 43.083, 182.621, 985.557],
    "Show_cred": [2.614, 6.405, 21.555, 86.159, 407.319],
    "Verify_cred": [2.397, 2.445, 2.788, 7.972, 89.706]
}

# Save plots in the current folder
current_folder = "./"

# Save plots for each function
for function in pairing_less.keys():
    plt.figure(figsize=(10, 6))
    plt.plot(sizes, pairing_less[function], label="Pairing-less KVAC", marker='o')
    plt.plot(sizes, pairing_based[function], label="Pairing-based KVAC", marker='o')
    plt.xlabel("Input Size (S_size, D_size)")
    plt.ylabel("Execution Time (ms)")
    plt.title(f"Execution Time Comparison for {function}")
    plt.yscale('log')  # Logarithmic scale for better visualization
    plt.legend()
    plt.grid(True)
    file_path = os.path.join(current_folder, f"{function}_execution_time_comparison.pdf")
    plt.savefig(file_path)  # Save the plot
    plt.close()

current_folder