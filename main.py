from fastapi import FastAPI, HTTPException, Request
from typing import List
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt

SECRET_KEY = "adriana-cuellar"
ALGORITHM = "HS256"

fake_db = {"users": {}}

app = FastAPI()

# Password hashing configuration
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(BaseModel):
    username: str
    password: str

class Payload(BaseModel):
    numbers: List[int]

class BinarySearchPayload(BaseModel):
    numbers: List[int]
    target: int

# Create an API route for user registration with the following specifications: The route should be /register and use the POST method. It must accept a JSON body containing username and password fiels. (e.g., {"username": "user1", "password": "pass1"}). On successful registration, the API should returno a JSON response with the message {"message": "User registered successfully."} and a status code 200. If the user already exists, the API should return a JSON response with the message {"message": "User already exists."} and a status code 400.          

#? This function handles user registration for the API. It takes a `User` object as input, which contains the username and password provided by the user. The function first checks if the username already exists in the `fake_db` dictionary. If the username is found, it raises an `HTTPException` with a 400 Bad Request status code and a "User already exists." error message.
# If the username is not found, the function hashes the provided password using the `pwd_context.hash()` method and stores the username and hashed password in the `fake_db` dictionary. Finally, it returns a JSON response with the message "User registered successfully." and a 200 OK status code.
@app.post("/register")
def register_user(user: User):
    if user.username in fake_db["users"]:
        raise HTTPException(
            status_code=400,
            detail={"message": "User already exists."}
        )
    
    # Hash the password before storing
    hashed_password = pwd_context.hash(user.password)
    fake_db["users"][user.username] = {
        "username": user.username,
        "password": hashed_password
    }
    print(fake_db)
    return {"message": "User registered successfully."}

# Create an API route for user login with the following specifications: The route should be /login and use the POST method. It must accept a JSON body containing username and password fields (e.g., {"username": "user1", "password": "pass1"}). On successful login, the API should return a JSON response with an access_token (e.g., {"access_token": <access_token>}) and a status code of 200. If the credentials are invalid, the API should respond with a status code of 401 and an appropriate error message.

#? This function handles user login for the API. It takes a `User` object as input, which contains the username and password provided by the user. The function first checks if the username exists in the `fake_db` dictionary. If the username is not found, it raises an `HTTPException` with a 401 Unauthorized status code and an "Invalid credentials" error message.
#? If the username is found, the function retrieves the stored user information from `fake_db` and verifies the provided password against the stored hashed password using the `pwd_context.verify()` method. If the password is invalid, it raises another `HTTPException` with a 401 Unauthorized status code and an "Invalid credentials" error message.
#? If the username and password are valid, the function generates an access token using the `jwt.encode()` method, with the username as the payload and the `SECRET_KEY` and `ALGORITHM` as the signing parameters. The access token is then returned in the response as a JSON object with the key "access_token".
@app.post("/login")
def login_user(user: User):
    if user.username not in fake_db["users"]:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )
    
    stored_user = fake_db["users"][user.username]
    if not pwd_context.verify(user.password, stored_user["password"]):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )
    
    access_token = jwt.encode(
        {"username": user.username},
        SECRET_KEY,
        algorithm=ALGORITHM
    )
    
    return {"access_token": access_token}

# Create a simple function to protect API endpoints by verifying the presence and validity of a token query parameter in incoming requests. The function should check if the token parameter is included in the query string of the request. If the token is missing or invalid, the function should respond with a status code of 401 and an appropriate error message indicating "Invalid Credentials" or "Authorization Failed." If the token is valid, the function should allow the request to proceed to the next handler and ensure a status code of 200 for a successful operation. 
#? Verifies the validity of the provided token for API authentication.  
#?     This function takes a token string as input and performs the following checks:
#?     1. Decodes the token using the `SECRET_KEY` and `ALGORITHM` to extract the payload.
#?     2. Checks if the token has expired by catching the `jwt.ExpiredSignatureError` exception and raising an `HTTPException` with a 401 Unauthorized status code and "Invalid Credentials" detail.
#?     3. Checks if the token is invalid by catching the `jwt.InvalidTokenError` exception and raising an `HTTPException` with a 401 Unauthorized status code and "Authorization Failed" detail.
#?     4. Checks if the username in the token payload exists in the `fake_db` dictionary. If not, raises an `HTTPException` with a 401 Unauthorized status code and "Invalid Credentials" detail.
#?     5. If all checks pass, the function prints the payload and returns the payload.  
#?     This function is used to protect API endpoints by verifying the presence and validity of the token provided in the request.

def verify_token(token:str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise   HTTPException(
            status_code=401,
            detail="Invalid Credentials"
        )
    except jwt.InvalidTokenError:
        raise   HTTPException(
            status_code=401,
            detail="Authorization Failed"
        )
    if payload['username'] not in fake_db["users"]:
        raise HTTPException(
            status_code=401,
            detail="Invalid Credentials"
        )
    print (payload)
    return payload

# Create a protected API route for sorting a list of numbers using the Bubble Sort algorithm. The route should be /bubble-sort and use the POST method. It must accept a JSON body with a key numbers containing an array of numbers (e.g., {"numbers": [5, 2, 9, 1]}). The API should return a JSON response with the key numbers containing the sorted array (e.g., {"numbers": [1, 2, 5, 9]}). The system should verify the presence and validity of the token before processing the request. Status Codes: 200: Successful operation, returns the sorted numbers. 401: Authorization failed, invalid or missing token.
"""
Sorts a list of numbers using the Bubble Sort algorithm and returns the sorted list.

This API endpoint accepts a POST request with a JSON body containing a "numbers" key, which is an array of numbers to be sorted. The function first verifies the validity of the provided token using the `verify_token` function. It then creates a copy of the input numbers list, and performs the Bubble Sort algorithm to sort the numbers in ascending order. Finally, it returns a JSON response with the key "numbers" containing the sorted list.

Args:
    request (Request): The incoming HTTP request object.
    payload (Payload): A data model containing the "numbers" field with the input list of numbers.
    token (str): The authentication token provided in the request.

Returns:
    dict: A JSON response with the key "numbers" containing the sorted list of numbers.
"""
@app.post("/bubble-sort")
async def bubble_sort(request: Request, payload: Payload, token: str):
    verify_token(token)
    numbers = payload.numbers.copy()
    n = len(numbers)
    
    for i in range(n):
        for j in range(0, n - i - 1):
            if numbers[j] > numbers[j + 1]:
                numbers[j], numbers[j + 1] = numbers[j + 1], numbers[j]
    
    return {"numbers": numbers}

#Create a protected API route for filtering even numbers. The route should be /filter-even and use the POST method. It must accept a JSON body with a key numbers containing an array of numbers (e.g., {"numbers": [1, 2, 3, 4, 5]}). The API should return a JSON response with the key even_numbers, containing only the even numbers from the input array (e.g., {"even_numbers": [2, 4]}). This route requires authorization, so the token query parameter must be included in the request for the system to verify the user's identity and grant access to the endpoint. If the token is invalid or missing, the request should be rejected with a status code of 401.

"""
Filters a list of numbers to return only the even numbers.

This API endpoint accepts a POST request with a JSON body containing a "numbers" key, which is an array of numbers to be filtered. The function first verifies the validity of the provided token using the `verify_token` function. It then creates a new list containing only the even numbers from the input list, and returns a JSON response with the key "even_numbers" containing the filtered list.

Args:
    request (Request): The incoming HTTP request object.
    payload (Payload): A data model containing the "numbers" field with the input list of numbers.
    token (str): The authentication token provided in the request.

Returns:
    dict: A JSON response with the key "even_numbers" containing the list of even numbers from the input.
"""
@app.post("/filter-even")
async def filter_even(request: Request, payload: Payload, token: str):
    verify_token(token)
    numbers = payload.numbers
    even_numbers = [num for num in numbers if num % 2 == 0]
    return {"even_numbers": even_numbers}

# Create an API route for summing the elements of a list of numbers. The route should be /sum-elements and use the POST method. It must accept a JSON body containing a key numbers with an array of numbers (e.g., {"numbers": [5, 2, 9]}). The API should return a JSON response with the key sum containing the sum of the numbers (e.g., {"sum": 16}). This route requires authorization, meaning that the request must include a valid authentication token as a query parameter. If the token is missing or invalid, the API should respond with a status code of 401 (Unauthorized).

"""
Sums the elements of a list of numbers and returns the total sum.

This API endpoint accepts a POST request with a JSON body containing a "numbers" key, which is an array of numbers to be summed. The function first verifies the validity of the provided token using the `verify_token` function. It then calculates the sum of the numbers in the input list and returns a JSON response with the key "sum" containing the total sum.

Args:
    request (Request): The incoming HTTP request object.
    payload (Payload): A data model containing the "numbers" field with the input list of numbers.
    token (str): The authentication token provided in the request.

Returns:
    dict: A JSON response with the key "sum" containing the total sum of the numbers.
"""
@app.post("/sum-elements")
async def sum_elements(request: Request, payload: Payload, token: str):
    verify_token(token)
    numbers = payload.numbers
    total_sum = sum(numbers)
    return {"sum": total_sum}

#Create an authorized API route for finding the maximum value in a list of numbers. The route should be /max-value and use the POST method. It must accept a JSON body with a key numbers containing an array of numbers (e.g., {"numbers": [5, 2, 9, 1]}). The API should return a JSON response with the key max containing the highest value from the array (e.g., {"max": 9}). This route requires authorization, so a valid token must be included as a query parameter in each request to access the endpoint.

"""
Finds the maximum value in a list of numbers and returns it in a JSON response.

This API endpoint accepts a POST request with a JSON body containing a "numbers" key, which is an array of numbers to be processed. The function first verifies the validity of the provided token using the `verify_token` function. It then finds the maximum value in the input list of numbers and returns a JSON response with the key "max" containing the highest value.

Args:
    request (Request): The incoming HTTP request object.
    payload (Payload): A data model containing the "numbers" field with the input list of numbers.
    token (str): The authentication token provided in the request.

Returns:
    dict: A JSON response with the key "max" containing the maximum value from the input list of numbers.
"""
@app.post("/max-value")
async def max_value(request: Request, payload: Payload, token: str):
    verify_token(token)
    numbers = payload.numbers
    max_number = max(numbers)
    return {"max": max_number}

# Create a protected API route for binary search with the following specifications: The route should be /binary-search and use the POST method. It must accept a JSON body containing a numbers array (a list of sorted numbers) and a target integer (e.g., {"numbers": [1, 2, 3, 4], "target": 3}). The API should return a JSON response with two keys: found (a boolean indicating if the target number is in the list) and index (the index of the target number if found, or -1 if not found) (e.g., {"found": true, "index": 2}). The route requires authorization, so a valid token must be included as a query parameter to authenticate the request and allow access to the protected endpoint.

"""
Performs a binary search on a sorted list of numbers to find a target value.

This API endpoint accepts a POST request with a JSON body containing a "numbers" key, which is a sorted array of numbers, and a "target" key, which is the value to search for. The function first verifies the validity of the provided token using the `verify_token` function. It then performs a binary search on the input list of numbers to find the target value. If the target is found, the function returns a JSON response with the keys "found" set to True and "index" set to the index of the target value in the list. If the target is not found, the function returns a JSON response with the keys "found" set to False and "index" set to -1.

Args:
    request (Request): The incoming HTTP request object.
    payload (BinarySearchPayload): A data model containing the "numbers" and "target" fields.
    token (str): The authentication token provided in the request.

Returns:
    dict: A JSON response with the keys "found" (a boolean indicating if the target was found) and "index" (the index of the target value, or -1 if not found).
"""
@app.post("/binary-search")
async def binary_search(request: Request, payload: BinarySearchPayload, token: str):
    verify_token(token)
    numbers = payload.numbers
    target = payload.target
    
    left = 0
    right = len(numbers) - 1
    
    while left <= right:
        mid = (left + right) // 2
        
        if numbers[mid] == target:
            return {"found": True, "index": mid}
        elif numbers[mid] < target:
            left = mid + 1
        else:
            right = mid - 1
            
    return {"found": False, "index": -1}
