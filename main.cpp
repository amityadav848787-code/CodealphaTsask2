#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <random>
#include <limits>

#include "sha256.hpp"

using namespace std;

const string USER_FILE = "users.txt";

// Generate a random 16-character salt
string generateSalt()
{
    const string characters =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    random_device rd;
    mt19937 generator(rd());

    uniform_int_distribution<int> distribution(
        0,
        static_cast<int>(characters.size() - 1)
    );

    string salt;

    for (int i = 0; i < 16; i++)
    {
        salt += characters[distribution(generator)];
    }

    return salt;
}

// Hash password using salt
string hashPassword(const string& password, const string& salt)
{
    return SHA256::hash(salt + password);
}

// Check whether username already exists
bool usernameExists(const string& username)
{
    ifstream file(USER_FILE);

    if (!file)
    {
        return false;
    }

    string line;

    while (getline(file, line))
    {
        stringstream ss(line);

        string storedUsername;

        getline(ss, storedUsername, '|');

        if (storedUsername == username)
        {
            return true;
        }
    }

    return false;
}

// Registration function
bool registerUser()
{
    string username;
    string password;

    cout << "\n========== REGISTRATION ==========\n";

    cout << "Enter username: ";
    cin >> username;

    // Basic username validation
    if (username.empty() ||
        username.find('|') != string::npos)
    {
        cout << "Invalid username.\n";
        return false;
    }

    // Check duplicate username
    if (usernameExists(username))
    {
        cout << "Username already exists.\n";
        return false;
    }

    cout << "Enter password: ";
    cin >> password;

    // Basic password validation
    if (password.length() < 6 ||
        password.find('|') != string::npos)
    {
        cout << "Password must contain at least 6 characters.\n";
        return false;
    }

    // Generate unique salt
    string salt = generateSalt();

    // Hash password
    string passwordHash =
        hashPassword(password, salt);

    // Store username, salt and hash
    ofstream file(USER_FILE, ios::app);

    if (!file)
    {
        cout << "Error: Unable to open user database.\n";
        return false;
    }

    file << username
         << "|"
         << salt
         << "|"
         << passwordHash
         << "\n";

    file.close();

    cout << "Registration successful!\n";

    return true;
}

// Login function
bool loginUser()
{
    string username;
    string password;

    cout << "\n============== LOGIN ==============\n";

    cout << "Enter username: ";
    cin >> username;

    cout << "Enter password: ";
    cin >> password;

    ifstream file(USER_FILE);

    if (!file)
    {
        cout << "No registered users found.\n";
        return false;
    }

    string line;

    while (getline(file, line))
    {
        stringstream ss(line);

        string storedUsername;
        string storedSalt;
        string storedHash;

        getline(ss, storedUsername, '|');
        getline(ss, storedSalt, '|');
        getline(ss, storedHash, '|');

        if (storedUsername == username)
        {
            string enteredHash =
                hashPassword(password, storedSalt);

            if (enteredHash == storedHash)
            {
                cout << "Login successful!\n";
                cout << "Welcome, " << username << "!\n";

                file.close();
                return true;
            }

            cout << "Incorrect password.\n";

            file.close();
            return false;
        }
    }

    file.close();

    cout << "Username not found.\n";

    return false;
}

int main()
{
    int choice;

    cout << "=====================================\n";
    cout << "     LOGIN & REGISTRATION SYSTEM\n";
    cout << "=====================================\n";

    do
    {
        cout << "\n";
        cout << "1. Register\n";
        cout << "2. Login\n";
        cout << "3. Exit\n";

        cout << "\nEnter your choice: ";

        if (!(cin >> choice))
        {
            cout << "Invalid input.\n";

            cin.clear();

            cin.ignore(
                numeric_limits<streamsize>::max(),
                '\n'
            );

            continue;
        }

        switch (choice)
        {
            case 1:
                registerUser();
                break;

            case 2:
                loginUser();
                break;

            case 3:
                cout << "Thank you for using the system.\n";
                break;

            default:
                cout << "Invalid choice. Please try again.\n";
        }

    } while (choice != 3);

    return 0;
}