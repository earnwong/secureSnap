# secureSnap
- Make sure to have easygui installed 
    - installation: pip install easygui 

## Running the code
- Start the server by running 
    -  python3 server.py <port>
- Then you can start two clients 
    - python3 client.py 'localhost' <port>

When logging in, you can use one of these usernames in the system or you can make a new one:
    - Username: bob, Password: Bob12345!
    - Username: samantha, Password: Sam12345!
    - Username: cathy, Password: Cathy12345!

You can choose whether you want to send or receive photos. 
- If you select "send photo", a pop up will appear where you can browse who you want to send the photo to. 
    - Once you select your recipient, you will then be prompted with another window that allows you to upload a file
- If you select "Continue", then the system will wait for someone to send you something.
- If you select "Quit" you will be logged out. 