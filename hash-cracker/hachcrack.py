import hashlib

# Function to detect hash type based on length
def detect_hash_type(hash_value):
    length = len(hash_value)
    if length == 32:
        return "MD5"
    elif length == 40:
        return "SHA-1"
    elif length == 64:
        return "SHA-256"
    else:
        return "Unknown Hash Type"

# Function to crack hash using dictionary attack
def crack_hash(hash_value, hash_type):
    # Sample dictionary of common passwords (you can expand this)
    passwords = ["password123", "123456", "letmein", "welcome", "qwerty", "admin", "12345"]
    
    for password in passwords:
        # Hash the password based on the detected hash type
        if hash_type == "MD5":
            hashed_password = hashlib.md5(password.encode()).hexdigest()
        elif hash_type == "SHA-1":
            hashed_password = hashlib.sha1(password.encode()).hexdigest()
        elif hash_type == "SHA-256":
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
        else:
            return "Unknown hash type for cracking"
        
        # Compare if the hashed password matches the input hash
        if hashed_password == hash_value:
            return password
    return "Password not found in dictionary"

# Main function to handle user input and processing
def main():
    # Ask user to input a hash value
    hash_value = input("Enter the hash to crack: ").strip()

    # Detect the hash type
    hash_type = detect_hash_type(hash_value)
    print(f"Detected hash type: {hash_type}")

    if hash_type == "Unknown Hash Type":
        print("The hash type is not recognized. Please check the hash length.")
        return

    # Attempt to crack the hash using dictionary attack
    cracked_password = crack_hash(hash_value, hash_type)

    # Output the result
    if cracked_password == "Password not found in dictionary":
        print("The password could not be cracked using the dictionary.")
    else:
        print(f"The cracked password is: {cracked_password}")

# Run the program
if __name__ == "__main__":
    main()
