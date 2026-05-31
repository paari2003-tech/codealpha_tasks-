# We are going build a vulnerable block of code to demonstrate the given task.

# Initially, The following code will vulnerable to multiple types of attacks, such as SQL Injection & Hardcoded Credentials, etc.

# Our Ultimate goal is to identify and fix these vulnerabilities to make the code secure.

# Hence the task is named as Secure Code Review (we will review the code line by line to identify and fix the vulnerabilities).

# We are trying fix the Windows terminal encoding issue by reconfiguring the standard output to use UTF-8 encoding. 

# This is necessary to ensure that the terminal can correctly display a wide range of characters, including those from different languages and special symbols.
 
# By doing this, we can prevent potential issues with character encoding that may arise when the terminal tries to display certain characters.


import sys
sys.stdout.reconfigure(encoding='utf-8')

# 1st Vulnerability : SQL Injection

# We are going Import certain modules/libraries that are necessary for our code to function properly.

import os           # Used to read environment variables and interact with the operating system.
import sqlite3      # Used to connect to and interact with a SQLite database (This a built-in python database library).
import hashlib      # Used to securely hash data, such as passwords.(for encrypting the password before storing it in the database).

# Now ,we are going create a connection to the SQLite database and create a cursor object to execute SQL commands.

# and also create a table to store user information if it doesn't already exist.which we are going try our SQL Injection attack on it.

def setup_database(): # creating a function to setup the database and create the users table if it doesn't exist.
    conn=sqlite3.connect('users.db')  # Connect to the SQLite database (or create it if it doesn't exist).
    cursor=conn.cursor()  # Create a cursor object to execute SQL commands.(Just like pen writing on a paper which writes the SQL commands to the database).

    # Now creating a table with "id","username","password" columns if it doesn't already exist.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    # Inserting a sample user into the users table that we just now we created , for testing purposes.

    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'passwor123')")  # Inserting a sample user into the users table if it doesn't already exist (to ensure we have a user to test with).
    conn.commit()  # Commit the changes to the database.
    conn.close()  # Closing the database connection.

    # Now the database setup is complete and ready for use.

print("\n Database setup complete. Sample user added.\n") 
print("\n Username: admin \n")
print("\n Password: passwor123\n")
    
# Printing the database setup completion message along with the sample user's credentials for testing purposes & also checking for errors in the database setup process.

setup_database() # calling the setup_database function to execute the DB setup process.

# The Vulernability test 1 : SQL Injection

def vul_login(username,password):
    conn=sqlite3.connect('users.db')    # Connect to the SQLite database
    cursor=conn.cursor()                # Create a cursor object to execute our SQL commands.
    query=f"SELECT * FROM users WHERE username='{username}' AND password='{password}'" 
    
    # This is the vulnerable SQL query that is susceptible to SQL Injection attacks.
    
    print(f"\n Query sent to the database : {query}\n")     # Printing the query to see how it looks like before executing it.
    print(f"{query}\n")                                     # Printing the query again for better visibility.
    cursor.execute(query)                                   # Executing the vulnerable SQL query.
    user=cursor.fetchone()                                  # Fetching the first result from the query which will executed now
    conn.close()                                            # Closing the database connection.
    if user:                                                # Condition to check if a user is found in the database with the provided username and password.
        print(f"\n Login successful. Welcome, {user[1]}!\n")
    else:
        print("\n Login failed. Invalid username or password.\n")
# Now we are going to test the vulnerable login function with a normal login attempt and then with an SQL Injection attack.

print("\n Testing normal login attempt with correct credentials:\n")
vul_login('admin','passwor123')                     # Testing the vulnerable login function with correct credentials.

print("\n Testing normal login attempt with incorrect credentials:\n")
vul_login('admin','wrongpassword')                  # Testing the vulnerable login function with incorrect credentials.

print("\n Testing SQL Injection attack:\n")
vul_login("admin' --", 'not_correct_password')      # Testing the vulnerable login function with an SQL Injection attack.

# we know that 'f' will directly insert a variable into the string without strain formatting, which is what makes it vulnerable to SQL Injection attacks.

#   when we used 'admin'--' , it will comment out the rest of the SQL query after the username , which allows easy bypass.
#   hence make the code highly vulnerable to SQL Injection attacks.

# The Cure : Parameterized Queries (Prepared Statements)
def secure_login(username,password):
    conn=sqlite3.connect('users.db') # Connect to the SQLite DB
    cursor=conn.cursor()             # Create a cursor object to execute SQL commands.
    query="SELECT * FROM users WHERE username=? AND password=?" # This is the parameterized SQL query that is not vulnerable to SQL Injection attacks.

    print(f"\n Query sent to the database : {query}\n") # Printing the query to see how it looks like before executing it.
    print(f"Values passed to the query: ({username}, {password})\n") 
    cursor.execute(query, (username, password))     # Executing the parameterized SQL query with the provided values.
    user=cursor.fetchone()                          # Fetching the first result from the query.
    conn.close()                                    # Closing the database connection.
    if user:                                        # Condition to check if a user is found in the database with the provided username and password.
        print(f"\n Login successful. Welcome, {user[1]}!\n")
    else:
        print("\n Login failed. Invalid username or password.\n")
    
    # Now we are going to test the secure login function with a normal login attempt and then with an SQL Injection attack.

print("\n Testing normal login attempt with correct credentials:\n")
secure_login('admin','passwor123')                     # Testing the secure login function with correct credentials.
print("\n Testing normal login attempt with incorrect credentials:\n")
secure_login('admin','wrongpassword')                  # Testing the secure login function with incorrect credentials
print("\n Testing SQL Injection attack:\n")
secure_login("admin' --", 'not_correct_password')      # Testing the secure login
# function with an SQL Injection attack.
    
# Now , we can see that the secure login function is not vulnerable to SQL Injection attacks and it will not allow the attacker to bypass the authentication process.

# 2nd Vulnerability : Hardcoded Credentials

# Hardcoded values are actually pre-defined values that are directly written into the code.
 
# Which can be easily accessed and exploited by attackers if they gain access to the source code.

# An example : If hardcoded my pasword in the code like this : password = "mysecretpassword" .
# then anyone who has access to the code can see my password and use it to gain unauthorized access to my accounts or systems.

# This is a major security risk because it can lead to data breaches, unauthorized access, and other security incidents.

# An Vulernability Example : 

print ("\n Example of hardcoded credentials vulnerability:\n")
hardcoded_password = "passwor123" # This is a hardcoded password which is a vulnerability.
print(f"[!] Vulerable - Password is hardcoded in the code : {hardcoded_password}\n") # Printing the hardcoded password to demonstrate the vulnerability.
print("[!] Anyone who reads this file can see the password !\n") # Printing a message to highlight the risk of hardcoded credentials.

# The Solution : Environment Variables

# We use Enviroment variables to store sensitive information like credentials, API keys, etc. outside of the source code.

# That way, even if someone gains access to the source code, they won't be able to see the sensitive information.

# os module in the code is used to read environment variables using os.getenv() function.

# We can set environment variables in our operating system or use a .env file to store them securely.

secure_password = os.getenv('DB_PASSWORD', 'not_set') # Reading the password from an environment variable named 'DB_PASSWORD'.

print(f"\n Secure - Password is read from environment variable : {secure_password}\n") # Printing the password read from the environment variable to demonstrate the solution.

# Now , We are to test what happens 

if secure_password == "not_set" :
    print("\n [!] Environment variable 'DB_PASSWORD' is not set. Please set it to a secure value.\n") 
    # Printing a warning message if the environment variable is not set.")
else:
    print("\n [+] Enviroment variable 'DB_PASSWORD' is set. Password is securely stored outside the code.\n")
    # Printing a success message if the environment variable is set, indicating that the password is securely stored outside the code.
    print("\n Our passcode is now secure and not visible in the source code, which reduces the risk of unauthorized access if someone gains access to the code.\n   ")

# Now we have successfully identified and fixed two major vulnerabilities in our code: SQL Injection and Hardcoded Credentials. 

# Finally , we can run it in banit to see the results and verify that our fixes are working as intended.


