from collections import Counter
import numpy as np

with open(r'Mandatory Assignments\Cryptanalysis of Ciphertexts\cipher_2.txt') as f:
    cipher_2 = f.read()

cipher_2 = cipher_2.replace("\n", "")
characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_#"
max_key_length = 20
english_letter_freq = {
    'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7, 'S': 6.3, 'H': 6.1, 'R': 6.0,
    'D': 4.3, 'L': 4.0, 'C': 2.8, 'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2, 'G': 2, 'Y': 2.0,
    'P': 1.9, 'B': 1.5, 'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10, 'Z': 0.074
}


def index_of_coincidence(sequence):
    N = len(sequence)
    frequencies = Counter(sequence)
    ic = sum(f * (f - 1) for _, f in frequencies.items()) / (N * (N - 1))
    return ic


def calculate_frequencies_for_key_length(cipher, key_length):
    chunks = [cipher[i::key_length] for i in range(key_length)]
    ics = [index_of_coincidence(chunk) for chunk in chunks]
    avg_ic = np.mean(ics)
    return avg_ic


def frequency_distribution(text):
    freq_dist = Counter(text)
    freq_dist = {char: freq_dist.get(char, 0) / len(text) for char in characters}
    return freq_dist


def caesar_shift(sequence, shift):
    shifted_sequence = ''
    for char in sequence:
        if char in characters:
            shifted_sequence += characters[(characters.index(char) - shift) % len(characters)]
        else:
            shifted_sequence += char
    return shifted_sequence


def chi_squared_statistic(text, expected_freq):
    observed_freq = frequency_distribution(text)
    chi_squared = 0
    for char in characters:
        observed = observed_freq[char]
        expected = expected_freq[char] if char in expected_freq else 0
        chi_squared += ((observed - expected) ** 2) / expected if expected else 0
    return chi_squared


def find_best_shift_for_column(column):
    chi_squared_by_shift = {}
    for shift in range(len(characters)):
        shifted_column = caesar_shift(column, shift)
        chi_squared = chi_squared_statistic(shifted_column, english_letter_freq)
        chi_squared_by_shift[shift] = chi_squared
    best_shift = min(chi_squared_by_shift, key=chi_squared_by_shift.get)
    return best_shift


def apply_shifts_to_columns(columns, shifts):
    decoded_columns = []
    for i, column in enumerate(columns):
        shift = shifts[i]
        decoded_column = caesar_shift(column, shift)
        decoded_columns.append(decoded_column)
    return decoded_columns


def interleave_columns(columns):
    interleaved_text = ''
    for i in range(len(columns[0])):
        for column in columns:
            if i < len(column):
                interleaved_text += column[i]
    return interleaved_text


# Step 1 - Calculate IC for each key length
ics_by_length = {l: calculate_frequencies_for_key_length(cipher_2, l) for l in range(1, max_key_length + 1)}

# Step 2 - Find the key length with the highest IC
total_freq = sum(english_letter_freq.values())
english_letter_freq = {char: freq / total_freq for char, freq in english_letter_freq.items()}

# Step 3 - Find the best shift for each column
key_length = 12
columns = [cipher_2[i::key_length] for i in range(key_length)]
best_shifts = [find_best_shift_for_column(column) for column in columns]
best_shifts

# Step 4 - Decode the text
decoded_columns = apply_shifts_to_columns(columns, best_shifts)
decoded_text = interleave_columns(decoded_columns)
print(decoded_text[:500])
