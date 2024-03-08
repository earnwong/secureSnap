# secureSnap
- Make sure to have easygui installed 
    - installation: pip install easygui 

## Running the code
- Start the server by running 
    -  python3 server.py <port>
- Then you can start two clients 
    - python3 client.py 'localhost' <port>

When prompted for a username, you can only use:
    - bobs
    - samantha
    - cathy 

You can choose whether you want to send or receive files. 
- If you select "send", a pop up will come up and you can select a jpg file. 
    - You will also be prompted for a recipient username.
- If you select "receive", then the system will wait for someone to send you something.