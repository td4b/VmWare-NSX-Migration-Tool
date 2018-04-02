[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This script is designed to automatically tag systems from the Provided CSV file and then generate NSX Baseline security policies to allow 
baseline connectivity over the network.

The idea is to allow machines to talk innitially by tagging the systems, the application traffic can then be analyzed using an
IDS/IPS to lock down the traffic via a Service-Instance 3rd party security service in NSX such as a Palo Alto firewall.

Moreover more analytical tools such as vRNI (vRealize Network Insight) can be used to characterize flow and lock down applications in the 
Datacenter environment.

This tools is intended to be used for Systems that are being migrated into a virtual environment as this sort of thing should be locked down 
from a Zero Day perspective if we were Building out the application.

**Required Software**

* Ansible

* Python 3.4+
  * ansible_vault
  * getpass
  * re
  * requests
  * xmltodict
  * json
  * pyvmomi

