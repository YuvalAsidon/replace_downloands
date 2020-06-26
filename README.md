# replace_downloands
Replacing .exe downloads with any kind of download we provide beforehand and bypassing https by sslstrip

## Install netfilterqueue
* sudo apt install python3-pip git libnfnetlink-dev libnetfilter-queue-dev
* pip3 install -U git+https://github.com/kti/python-netfilterqueue

## Running the program
* need to downlad the [arp_spoofing](https://github.com/YuvalAsidon/ARP_Spoofing)
  * download file and place it in the same place as this file
* if you want to activate it on another pc on the network:
  * change in both files the IP's of everything and change the website that you want to try it on
* change what file you want to make the target pc download instead
* sudo python replace_downloads.py
* In order to terminate the program program, CTRL+C in both terminals that gets open
