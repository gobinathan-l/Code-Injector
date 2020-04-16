#  Code Injector. 
A Python Script to Inject custom HTML or JavaScript into Webpages of Remote or Local Computers.

  - Injects Custom Code into Webpages.
  - Supports Remote Computer (Arp Spoofed) and Local Computer.
  - Downgrades the HTTP to HTTP/1.0.

### Installation

To Clone the Code Injector Repository..

```sh
# git clone https://github.com/gobinathan-l/Code-Injector.git
# cd Code-Injector
```

To install Dependencies..

```sh
# pip install -r requirements.txt
```

To Execute the Script..
```sh
# python Code_Injector.py -h
# python3 Mac_Changer.py -m remote

Enter the Script to be Injected >> <script>alert('injected code');</script>
```

In case of HTTP versions other than HTTP/1.1, The Script doesn't perform HTTP Downgrade Attacks. If you want the script to work for other HTTP version, replace the "HTTP/1.1" (line 43) in the Script with your HTTP Version.

### About Author
I am Gobinathan, a CyberSecurity Enthusiast. To reach out to me..<br>
[GitHub](https://github.com/gobinathan-l/), [Linkedin](https://in.linkedin.com/in/gobinathan-l), [Twitter](https://twitter.com/gobinathan_l)


***Suggestions on Improvements and New Features are Welcome.***