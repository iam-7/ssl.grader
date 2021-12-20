# ssl.grader
SSL Grader, is a python script that can be used to grade the implementation of SSL\TLS and Digital certificate 

Setup:

When hostsfile is used for grading csv file should be placed under root folder of this script.

usage: 

ssl-grader.py [-h] [--mode mode] [--hostname hostname] [--hostsfile hostsfile]

Script will score the domain SSL\TLS implementation.
 script usage:
 #> python ssl-grader.py --mode 1 --hostname domain.com
 #> python ssl-grader.py --mode 2 --hostsfile hosts.csv

optional arguments:
  -h, --help            show this help message and exit
  --mode mode           Script can run in two modes.
                         1 -> Run on single host
                         2 -> Run on list of hosts from the csv file
  --hostname hostname   hostname of the server to score
  --hostsfile hostsfile
                        Hosts file in csv
