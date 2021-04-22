# hardening-tests
Just some files to play with during hardening tests

This file <wazuh-agent-install-hardening.sh> will make the proper arrangements to install Ansible in a Cubic project and automate some hardening.
It will also install the Wazuh Agent, so you will need to have a Wazuh Manager listening to it in the same network.
The script uses the proper SCA Template for providing statistics and details about CIS Benchmarks compliance, in the SCA section in the Wazuh Dashboard.
The two only versions tested are: Ubuntu 18.04 and 20.04.
It is for a very specific environment, so this script will not be useful for general purposes.
The script downloads from the current directory all it needs. No breakpoints are enabled, so if you want to have a more granular control of the actions or functions, uncomment the breakpoints (well marked).
