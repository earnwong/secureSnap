# secureSnap
- Make sure to have the following modules installed: easygui, pip install email_validator
    - installation: pip install easygui, email_validator

## Running the code
- Start the server by running (cd into server)
    -  python3 server.py <port>
- Then you can start the client using the following command (do not cd into server)
    - python3 client/client.py 'localhost' <port>

## Known Error
- With the SSL Version: OpenSSL 3.0.11 19 Sep 2023, we get this error sometimes: Error while receiving photos: [SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:2559)
- However, with the older SSL version: OpenSSL 1.1.1l 24 Aug 2021, we don't get this error
- At this time, we do not have a solid way to fix this. Chat suggests to enable legacy support in OpenSSL 3.0. 
- **For the purposes of testing, if you get this error, restart the code!** 

## Loggging In
- When logging in, you can do the following to test out or code:
    - Superadmin: If you want to log in as a superadmin, type 'superadmin' for username, and "Superadmin1!" for the password. 
    - User: You can create a user using your own email as the username. You will be sent a verification email which will walk you through the account setup.
    - Admin: You can create from the superadmin account. 

## Send Photo
- If you select "send photo", a pop up will appear where you can browse who you want to send the photo to. 
- Once you select your recipient, you will then be prompted with another window that allows you to upload a file
- Photos should be sent to you automatically

## Block Users
- To see who to block, you can look into the userinfo.csv and test out other users to block, admin, superadmin, etc..

## View Logs
- You can view logs from an admin or superadmin account

## Other Features
- Other features to test out should be intuitive! You can refer to the documentation for further information 