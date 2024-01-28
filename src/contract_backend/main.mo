// Define a user structure to store user data.
type User = {
  username: Text;
  passwordHash: Text;
};

// Define a smart contract for user authentication.
actor class AuthContract {

  // Store user data in a Jug Hash Table.
  var users: Jug<Text, User> = Jug();

  public shared() func init() {};

  // Register a new user with a username and password.
  public shared({caller} : {caller: Principal}, username: Text, password: Text) : async Text {
    // Ensure the caller is the system principal (admin).
    assert(caller == Principal.fromActor(this), "Access denied. Only the system can register users.");

    // Check if the user already exists.
    if (users.exists(username)) {
      return "User already exists.";
    }

    // Hash the user's password for security.
    let passwordHash = hashPassword(password);

    // Create a new user and store their data.
    let user = { username = username; passwordHash = passwordHash };
    users.insert(username, user);

    return "User registered successfully.";
  };

  // Authenticate a user with a username and password.
  public shared({caller} : {caller: Principal}, username: Text, password: Text) : async Text {
    // Ensure the caller is the user trying to authenticate.
    assert(caller == Principal.fromActor(this), "Access denied. You can only authenticate yourself.");

    // Check if the user exists.
    if (!users.exists(username)) {
      return "User does not exist.";
    }

    // Retrieve the user data and check the password.
    let user = users.get(username);
    if (user.passwordHash == hashPassword(password)) {
      return "Authentication successful.";
    } else {
      return "Authentication failed. Invalid password.";
    }
  };

  // Helper function to hash the password (a simple example, not recommended for production).
  public func hashPassword(password: Text) : Text {
    // In a real system, you would use a secure password hashing library.
    return Text.fromNat(Hash.sha256(encodeUtf8(password)));
  };
};
