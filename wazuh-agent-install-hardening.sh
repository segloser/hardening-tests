#!/bin/bash
## Basic dirty non-sanitized Wazuh Agent Installation Script
## and Hardening automation through Ansible.
## This script is conceived to be run once, to prepare a 
## OS hardened template to work with Wazuh 
## in a very specific environment (Cubic), that conditions restrictions.

## Legend
## [i] - Informational text
## [r] - Action requested / User input needed
## [w] - Warning!

LOG="/tmp/wazuh-install.log"
echo -n "\n============================="
echo -n "$(date)" >> $LOG
echo -n "=============================" >> $LOG

VERSIONCHECK=$(cat /etc/os-release  | grep VERSION_ID | grep -Eo "[0-9]{2}.[0-9]{2}")
function check_ubuntu_version(){

	if [[ $VERSIONCHECK == "20.04" ]]
	then
		VERSION="20"
	elif [[ $VERSIONCHECK == "18.04" ]]
	then
		VERSION="18"
	else
		echo "This script is not tested for the detected version"
	fi
}
check_ubuntu_version

function sudo_check(){
	clear
	# Run me as sudo 
	if [[ $EUID -ne 0 ]]
	then
		clear
		echo "[i] - This script must be run as root (sudo)"
		echo "[i] - Exiting now."
		exit 1
	fi
}
sudo_check

# Temporarily disabling unattended upgrades
function update_disabling(){
	echo "Disabling Unattended-Upgrades"
	sed -i 's/APT::Periodic::Unattended-Upgrade "1"/APT::Periodic::Unattended-Upgrade "0"/g' /etc/apt/apt.conf.d/20auto-upgrades

	echo "Killing updating processes, to unlock update functionalities for the script"
	ps aux | grep "/usr/lib/apt/apt.systemd.daily" | grep -v grep| awk {'print $2'} > /tmp/tokill
	ps aux | grep "/run/mlocate.daily.lock" | grep -v grep| awk {'print $2'} >> /tmp/tokill
	ps aux | grep "apt-check" | grep -v grep| awk {'print $2'} >> /tmp/tokill

	for PID in $(cat /tmp/tokill)
	do
		sudo kill $PID
	done

	sudo rm /var/cache/apt/archives/lock
	sudo rm /var/lib/dpkg/lock
	sudo rm /var/lib/dpkg/lock-frontend
	##########################
	### CONTROL BREAKPOINT ###
	##########################
	###read -p "Lock files removed - Press ENTER to start"
}
update_disabling

# First apt update
function check_internet(){
	clear
	echo "[i] - As this should be a clean Ubuntu installation, I need to update..."
	echo "[i] - Checking Internet connection..."
	if [[ $(ping -c1 1.1.1.1 | grep -Eo "100% packet loss") == "100% packet loss" ]]
	then
		echo "[i] - No Internet connection."
		echo "[i] - Please, fix the connectivity issue and try again."
		echo "[i] - Exiting now."
		exit 1
	else
		echo "[i] - Ready to update the system."
	fi
}

check_internet
sudo apt update -y

# Purging Amazon Launcher in Ubuntu 18.04
if [[ $VERSION == "18" ]]
then
	echo "[i] - Removing the Amazon Launcher"
	sudo apt purge ubuntu-web-launchers -y
fi

# Installing curl
if [[ $(dpkg -s curl | grep -Eo "Status: install ok installed") == "Status: install ok installed" ]]
then
	echo "[i] - curl is already installed... Continuing the process..."
else
	echo "[i] - Installing curl..."
	echo "========================"
	sudo apt install curl -y
	sleep 3
fi

clear
# Wazuh GPG Key
function install_wazuh_key(){
	
	if [[ $(apt-key | grep -Eo "Wazuh.com") == "Wazuh.com" ]]
	then
		echo "[i] - Wazuh GPG Key is already installed"
	else
		echo "[i] - Installing Wazuh GPG Key..."
		echo "================================="
		sudo curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
	fi

	# Wazuh sources copied into sources.list
	if [[ $(cat /etc/apt/sources.list.d/wazuh.list | grep -Eo "deb https://packages.wazuh.com/4.x/apt/ stable main") == "deb https://packages.wazuh.com/4.x/apt/ stable main" ]]
	then
		echo "[i] - sources.listd/.wazuh.list already exists"
	else
		echo "[i] - Copying wazuh.list in /etc/apt/sources.list.d/"
		echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
	fi

	sleep 2
	clear
	echo "[i] - Updating the system..."
	sudo apt update
}

install_wazuh_key

# Defining the Wazuh apt install command function
function wazuh-install () {

	echo "[i] - Installting the Wazuh agent"
	sudo apt install wazuh-agent
	echo
}

# Installting Wazuh using the function
if [[ $(dpkg -s wazuh-agent | grep -Eo "Status: install ok installed") != "Status: install ok installed" ]]
then
        wazuh-install | tee /tmp/wazuh-install.txt
        while [[ $(cat /tmp/wazuh-install.txt | grep -Eo "E: Unable to locate package wazuh-agent") == "E: Unable to locate package wazuh-agent" ]]
        do
			echo "[i] - Wazuh installation failed for some unknown reason. Trying again in 3 seconds..."
			sleep 3
			wazuh-install | tee /tmp/wazuh-install.txt
		done
else
	echo "[i] - Wazuh-agent seems to be already installed... Continuing the process..."
	echo
	echo "WAZUHINSTALLED" >> $LOG
fi
sleep 2

# configuring the Manager IP in the ossec.conf file in /var/ossec/etc/ossec.conf
echo "[i] - Checking if the Wazuh agent configuration has been previously set"
if [[ $(cat /var/ossec/etc/ossec.conf | grep -Eo "MANAGER_IP") == "MANAGER_IP"  ]]
then
	clear
	echo "[i] - The Wazuh agent is NOT sending information to the Wazuh Manager"
	echo "[i] - You will need to find out your Wazuh Manager IP for the next step"
	##########################
	### CONTROL BREAKPOINT ###
	##########################
	###read -p "Press ENTER when ready to continue."
	echo
	echo
	echo "********************************"
	echo "* Setting the Wazuh Manager IP *"
	echo "********************************"
	echo
	echo "Wazuh Manager Default IP = 100.100.100.100"
	echo 
	echo -n "[r] - You have 10 seconds to write a custom IP, or a default value will be used insted \n Wazuh Manager IP: "
	read -t 10 IP
	if [[ $IP == "" ]]
	then
		IP="100.100.100.100"
	fi
	sed -i "s/      <address>MANAGER_IP<\/address>/     <address>$IP<\/address>/g" /var/ossec/etc/ossec.conf

	echo
	echo "[i] - The Manager's IP has been changed. Verify it in /var/ossec/etc/ossec.conf"
	echo
else
	echo "[i] - Your Wazuh agent has already been configured at some point. Check it manually."
fi

#
function cis_download(){
	
	echo
	echo "[i] - We need to download the CIS SCA Benchmark for Ubuntu $VERSION.04 L1"
	echo "[i] - This file should be provided by a remote or local security server"
	##########################
	### CONTROL BREAKPOINT ###
	##########################
	echo "[r] - Press ENTER to download the cis_ubuntu$VERSION-04_L1.yml file from its default location or add a new URL now): "
	read -t 0 CISURL
	cd /var/ossec/ruleset/sca

	if [[ $CISURL == "" ]]
	then
		CISURL="https://raw.githubusercontent.com/segloser/hardening-tests/main/cis_ubuntu$VERSION-04_L1.yml"
	fi
	wget $CISURL 
	chgrp ossec /var/ossec/ruleset/sca/cis_ubuntu$VERSION-04_L1.yml
	echo 'CISDOWNLOADED' >> $LOG
}

if [[ $(grep -Eo "CISDOWNLOADED" $LOG) == "" ]]
then 
	cis_download
	rm /var/ossec/ruleset/sca/debian*.yml
else
	echo "CIS SCA for Ubuntu $VERSION.04 already downloaded"
fi

# Installing SSH to implement a secure configuration.
# It will be uninstalled.
echo "Installing SSH"
echo "=============="
sudo apt install -y ssh

sleep 2
clear
echo 
echo "************************************************************************"
echo "* Ready to install Ansible. This includes installing Python 2.7        *"
echo "* in case of Ubuntu 18.04                                              *"
echo "*                                                                      *"  
echo "* Remember to unsinstall Python 2.7 when you finish with Ansible + CIS *"
echo "************************************************************************"

##########################
### CONTROL BREAKPOINT ###
##########################
###read -p "Press ENTER when ready"

function alter_ansible_install(){
	echo "[w] - It seems there is a problem installing Ansible in Cubic, we will start the alternative installation process..."
	rm -rf /tmp/ansible-alternative 
	mkdir /tmp/ansible-alternative
	cd /tmp/ansible-alternative
	wget  https://github.com/segloser/hardening-tests/raw/main/ansible_ubuntu_$VERSION-04.zip -O /tmp/ansible-alternative/ansible.zip
	unzip ansible.zip
	sudo dpkg -i ./*.deb
	echo "[i] - DEB packages installation process finished."
	echo "[i] - Checking installation..."
	if [[ $(dpkg -s ansible | grep -Eo "Status: install ok installed") == "Status: install ok installed" ]]
	then
		echo "[i] - Ansible is installed."
		ANSVARINSTALL="dpkg"
	else
		echo "[w] - Check why ansible cannot be installed."
		echo "[i] - Exiting the program now."
		exit 1
	fi
}

function ansi_install(){

	clear
	echo "Trying to install ansible via: apt install ansible -y"
	sudo apt install ansible -y

	if [[ $(dpkg -s ansible | grep -Eo "Status: install ok installed") != "Status: install ok installed" ]]
	then
		echo "Conventional installation failed. Trying alternative cached packages installation"
		alter_ansible_install
	else
		echo "[i] - Ansible seems to be properly installed."
		ANSVARINSTALL="apt"
	fi
}

ansi_install 

function install_git(){
	
	if [[ $(grep -Eo "GITINSTALLED" $LOG) == "" ]]
	then 
		echo
		echo "[i] - Installing git"
		sudo apt install git -y
		echo "GITINSTALLED" >> $LOG
	fi

	if [ ! -d "/opt/Ubuntu1804-CIS" ]
	then
		git clone https://github.com/florianutz/Ubuntu1804-CIS /opt/Ubuntu1804-CIS
	fi
}

install_git

cd /opt/Ubuntu1804-CIS

# Tailoring some files
sed -i 's/ubuntu1804cis_xwindows_required: false/ubuntu1804cis_xwindows_required: true/g' /opt/Ubuntu1804-CIS/defaults/main.yml
sed -i 's/ubuntu1804cis_selinux_disable: false/ubuntu1804cis_selinux_disable: true/g' /opt/Ubuntu1804-CIS/defaults/main.yml
sed -i 's/ubuntu1804cis_config_aide: true/ubuntu1804cis_config_aide: false/g' /opt/Ubuntu1804-CIS/defaults/main.yml
echo "- src: https://github.com/florianutz/Ubuntu1804-CIS.git" > /opt/Ubuntu1804-CIS/requirements.yml

# File fixing
sed -i 's/collections://g' /opt/Ubuntu1804-CIS/meta/main.yml
sed -i 's/  - ansible.posix//g' /opt/Ubuntu1804-CIS/meta/main.yml

##########################
### CONTROL BREAKPOINT ###
##########################
###read -p "[r] - About to start ansible-galaxy - Press ENTER"

ansible-galaxy install -p roles -r requirements.yml

sed -i 's/collections://g' /opt/Ubuntu1804-CIS/roles/Ubuntu1804-CIS/meta/main.yml
sed -i 's/  - ansible.posix//g' /opt/Ubuntu1804-CIS/roles/Ubuntu1804-CIS/meta/main.yml

sed -i 's/ubuntu1804cis_xwindows_required: false/ubuntu1804cis_xwindows_required: true/g' /opt/Ubuntu1804-CIS/roles/Ubuntu1804-CIS/defaults/main.yml
sed -i 's/ubuntu1804cis_selinux_disable: false/ubuntu1804cis_selinux_disable: true/g' /opt/Ubuntu1804-CIS/roles/Ubuntu1804-CIS/defaults/main.yml
sed -i 's/ubuntu1804cis_config_aide: true/ubuntu1804cis_config_aide: false/g' /opt/Ubuntu1804-CIS/roles/Ubuntu1804-CIS/defaults/main.yml

echo "Generating the playbook (my_console.yml)"
echo "- name: Harden Server" > /opt/Ubuntu1804-CIS/my_console.yml
echo "  hosts: localhost" >> /opt/Ubuntu1804-CIS/my_console.yml
echo "  become: yes" >> /opt/Ubuntu1804-CIS/my_console.yml
echo ""
echo "  any_errors_fatal: false" >> /opt/Ubuntu1804-CIS/my_console.yml
echo "  ignore_errors: true" >> /opt/Ubuntu1804-CIS/my_console.yml
echo "  roles:" >> /opt/Ubuntu1804-CIS/my_console.yml
echo "    - Ubuntu1804-CIS" >> /opt/Ubuntu1804-CIS/my_console.yml

sed -i 's/- name: generate new grub config\n  become: true\n  command: grub-mkconfig -o "{{ grub_cfg.stat.path }}"\n  notify: fix permissions after generate new grub config handler\n/- name: generate new grub config\n  become: true\n  command: grub-mkconfig -o "{{ grub_cfg.stat.path }}"\n  notify: fix permissions after generate new grub config handler\n  tags: grub_config\n/g'  /opt/Ubuntu1804-CIS/roles/Ubuntu1804-CIS/handlers/main.yml

## Function to add a tag in a specific paragraph
## Disabled by default. Only here just in case.
function add_tag(){
	echo '#!/user/bin/python' > /tmp/replace.py
	echo 'import re' >> /tmp/replace.py
	echo '' >> /tmp/replace.py
	echo 'filename = "/opt/Ubuntu1804-CIS/roles/Ubuntu1804-CIS/handlers/main.yml"' >> /tmp/replace.py
	echo '' >> /tmp/replace.py
	echo 'search_text = """' >> /tmp/replace.py
	echo '- name: generate new grub config' >> /tmp/replace.py
	echo '  become: true' >> /tmp/replace.py
	echo '  command: grub-mkconfig -o "{{ grub_cfg.stat.path }}"' >> /tmp/replace.py
	echo '  notify: fix permissions after generate new grub config handler' >> /tmp/replace.py
	echo '"""' >> /tmp/replace.py
	echo '' >> /tmp/replace.py
	echo 'replace_text = """' >> /tmp/replace.py
	echo '- name: generate new grub config' >> /tmp/replace.py
	echo '  become: true' >> /tmp/replace.py
	echo '  command: grub-mkconfig -o "{{ grub_cfg.stat.path }}"' >> /tmp/replace.py
	echo '  notify: fix permissions after generate new grub config handler' >> /tmp/replace.py
	echo '  tags: grub_config' >> /tmp/replace.py
	echo '"""' >> /tmp/replace.py
	echo '' >> /tmp/replace.py
	echo 'with open(filename, "r+") as f:' >> /tmp/replace.py
	echo '    text = f.read()' >> /tmp/replace.py
	echo '    text = re.sub(search_text, replace_text, text)' >> /tmp/replace.py
	echo '    f.seek(0)' >> /tmp/replace.py
	echo '    f.write(text)' >> /tmp/replace.py
	echo '    f.truncate()' >> /tmp/replace.py
	python /tmp/replace.py
}
#add_tag

# Installing auditd to implement a secure configuration
sudo apt install -y auditd
sleep 2
clear

##########################
### CONTROL BREAKPOINT ###
##########################
###read -p "[r] - Press ENTER when ready to play the book with Ansible"

# Skipping some rules and actions 
ansible-playbook /opt/Ubuntu1804-CIS/my_console.yml --skip-tags "aide, grub_config, rule_2.2.1.1, rule_2.2.3"

function ansible_remove(){
	
	if [[ $ANSVARINSTALL == "apt" ]]
	then
		sudo apt remove ansible -y

		# Installed packages
		echo "Removing installed packages"
		apt remove ieee-data libpython-stdlib libpython2.7 libpython2.7-minimal libpython2.7-stdlib python -y
		apt remove python-asn1crypto python-certifi python-cffi-backend python-chardet python-crypto -y
		apt remove python-cryptography python-enum34 python-httplib2 python-idna python-ipaddress python-jinja2 -y 
		apt remove python-jmespath python-kerberos python-libcloud python-lockfile python-markupsafe python-minimal -y 
		apt remove python-netaddr python-openssl python-paramiko python-pkg-resources python-pyasn1 python-requests -y 
		apt remove python-selinux python-simplejson python-six python-urllib3 python-xmltodict python-yaml python2.7 python2.7-minimal -y
		# Suggested packages
		echo "Removing suggested packages"
		apt remove cowsay sshpass python-doc python-tk python-crypto-doc python-cryptography-doc python-cryptography-vectors -y 
		apt remove python-enum34-doc python-jinja2-doc python-lockfile-doc ipython python-netaddr-docs  python-openssl-doc -y 
		apt remove python-openssl-dbg python-gssapi python-setuptools python-socks python-ntlm python2.7-doc binfmt-support -y
		# Recommended packages
		echo "Removing recommended packages"
		apt remove python-winrm -y
		# NEW packages
		echo "Removing NEW packages" 
		apt remove ansible ieee-data libpython-stdlib python python-asn1crypto python-certifi python-cffi-backend -y
		apt remove python-chardet python-crypto python-cryptography python-enum34 python-httplib2 python-idna -y 
		apt remove python-ipaddress python-jinja2 python-jmespath python-kerberos python-libcloud python-lockfile -y 
		apt remove python-markupsafe python-minimal python-netaddr python-openssl python-paramiko python-pkg-resources -y 
		apt remove python-pyasn1 python-requests python-selinux python-simplejson python-six python-urllib3 python-xmltodict -y 
		apt remove python-yaml python2.7 python2.7-minimal -y

		# Removing Terminator and associated packages
		apt remove terminator -y
		apt remove gir1.2-keybinder-3.0 libkeybinder-3.0-0 python-cairo python-dbus python-gi python-gi-cairo python-psutil -y
		apt remove python-dbus-dbg python-dbus-doc python-psutil-doc -y
		
	elif [[ $ANSVARINSTALL == "dpkg" ]]
	then
		sudo dpkg -r /tmp/ansible-alternative/*.deb
	fi
}

function restart_wazuh_agent(){
	if [[ $(grep -Eo "MANAGER_IP" /var/ossec/etc/ossec.conf) != "MANAGER_IP" ]]
	then
		service wazuh-agent restart
	else
		echo "Check your Wazuh Agent configuration. There is no MANAGER_IP properly set in the ossec.conf file."
		echo "You can check ossec.conf file in this directory: /var/ossec/etc"
	fi
}

## Ansible removal is disabled by default for the tests.
## Uncomment when ready to build your hardened template.
ansible_remove

function removing_misc(){

	sudo apt remove ssh -y

	# Clean the ruleset/sca directory and restart Wazuh
	[ -d /var/ossec/ruleset/sca/DISABLED  ] || mkdir /var/ossec/ruleset/sca/DISABLED
	[ -f /var/ossec/ruleset/sca/cis_debian10.yml ] && mv /var/ossec/ruleset/sca/cis_debian10.yml /var/ossec/ruleset/sca/DISABLED
	
	restart_wazuh_agent

	# Restoring unattended upgrades
	sed -i 's/APT::Periodic::Unattended-Upgrade "0"/APT::Periodic::Unattended-Upgrade "1"/g' /etc/apt/apt.conf.d/20auto-upgrades

	## Cleaning and Removing Previously added repository
	rm -rf /opt/Ubuntu1804-CIS
	sudo apt autoremove -y
	sudo apt autoclean
	sudo apt clean cache

	# Removes old revisions of snaps
	# CLOSE ALL SNAPS BEFORE RUNNING THIS
#	set -eu
#	snap list --all | awk '/disabled/{print $1, $3}' |
#		while read snapname revision; do
#			snap remove "$snapname" --revision="$revision"
#		done
		
	rm -rf ~/.cache/thumbnails/*
	#rm /tmp/replace.py
	history -c
}

## Misc software uninstall is disabled by default. 
## Uncomment to activate it when ready to build your hardened template.
removing_misc

exit 0
