import requests
import time

# Test the signup endpoint
def test_signup():
    url = "http://127.0.0.1:5000/signup"
    
    # Test GET request to signup page
    print("Testing GET request to signup page...")
    try:
        response = requests.get(url)
        print(f"Status Code: {response.status_code}")
        print(f"Response Length: {len(response.text)} characters")
        if response.status_code == 200:
            print("✓ Signup page is accessible")
        else:
            print("✗ Signup page is not accessible")
    except Exception as e:
        print(f"✗ Error accessing signup page: {e}")
    
    # Test POST request to signup endpoint
    print("\nTesting POST request to signup endpoint...")
    signup_data = {
        "username": "testuser" + str(int(time.time())),
        "email": "testuser" + str(int(time.time())) + "@example.com",
        "password": "TestPass123!",
        "confirm_password": "TestPass123!",
        "role": "customer"
    }
    
    try:
        response = requests.post(url, data=signup_data)
        print(f"Status Code: {response.status_code}")
        print(f"Response URL: {response.url}")
        if response.status_code == 200:
            print("✓ Signup POST request successful")
        elif response.status_code == 302:
            print("✓ Signup POST request successful with redirect")
        else:
            print("✗ Signup POST request failed")
    except Exception as e:
        print(f"✗ Error during signup POST request: {e}")

if __name__ == "__main__":
    test_signup()