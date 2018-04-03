[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This script is designed to automatically tag systems from the Provided CSV file and then generate NSX Baseline security policies to allow 
baseline connectivity over the network.

The idea is to allow machines to talk initially by tagging the systems, the application traffic can then be analyzed using an
IDS/IPS to lock down the traffic via a Service-Instance 3rd party security service in NSX such as a Palo Alto firewall.

Moreover more analytical tools such as vRNI (vRealize Network Insight) can be used to characterize flow and lock down applications in the 
Datacenter environment.

This tools is intended to be used for Systems that are being migrated into a virtual environment as this sort of thing should be locked down 
from a day zero perspective if we were Building out the application.

**Required Software - Complete Setup Instructions Below.**

* Python 3.4+
  * ansible_vault
  * getpass
  * re
  * requests
  * xmltodict
  * json
  * pyvmomi

**Installation:**
1) It's best practice to set up a virtualenv, package management becomes a lot easyier. Just place the script in the same directory as the bin file generated from the virtualenv script.
~~~
admin> apt-get install virtualenv
admin> virtualenv project --python=python3.6
admin> cd project
admin> source bin/activate
(project)admin>
~~~
2) Install the Dependency requirements with pip.
~~~
(project)admin> pip install -r requires.txt
~~~
3) Lastly encrypt the login.yaml file. Note: Use provided specs in "login_decrypted.yaml" replacing the appropriate values.
~~~
(project)admin> ansible-vault create login.yaml
New Vault password: ********
Confirm New Vault password: ********
(project)admin>
~~~
4) Run the script!
~~~
(project)admin> python migrate.py
~~~
