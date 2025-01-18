# Password-Strength-Evaluator-and-Breach-Checker
This project combines the concepts of password security and user awareness. It evaluates the strength of a password based on its complexity and checks if the password has appeared in known breaches using the Have I Been Pwned API. This helps users understand the importance of using strong, uncompromised passwords.
import hashlib
import requests

# Function to evaluate password strength
def evaluate_password_strength(password):
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()-_=+[]{}|;:'\",.<>?/" for c in password)
    
    score = sum([has_upper, has_lower, has_digit, has_special])
    
    if length >= 12 and score == 4:
        return "Strong"
    elif length >= 8 and score >= 3:
        return "Moderate"
    else:
        return "Weak"

# Function to check password against Have I Been Pwned API
def check_password_breach(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]
    
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    
    if response.status_code != 200:
        raise RuntimeError("Error fetching data from Have I Been Pwned API")
    
    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return int(count)
    return 0

# Main program
def main():
    print("Password Strength Evaluator and Breach Checker")
    password = input("Enter a password to check: ")
    
    # Evaluate password strength
    strength = evaluate_password_strength(password)
    print(f"\nPassword Strength: {strength}")
    
    # Check if password has been breached
    try:
        breach_count = check_password_breach(password)
        if breach_count > 0:
            print(f"Warning! This password has appeared in {breach_count} data breaches.")
            print("Avoid using this password.")
        else:
            print("Good news! This password has not been found in any known breaches.")
    except Exception as e:
        print(f"Error: {e}")

# Run the program
if __name__ == "__main__":
    main()
