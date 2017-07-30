#!/bin/bash

#9
clear
printf "Checking if Anacron is enabled \n"
if rpm -qa | grep -q cronie-anacron; then # List enabled softwares and grep "cronie-anacron" to check if it is enabled
	printf "\033[33;32m PASS \n"
else
	printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Checking if Cron is enabled \n"
if systemctl is-enabled crond | grep enabled >/dev/null; then #Use systemctl to check if cron is enabled
	printf "\033[33;32m PASS \n"
else
	printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Checking if /etc/anacrontab file has the correct permissions \n"
if ls -l /etc/anacrontab | grep -e -rw------- >/dev/null; then # Grep the permissions from ls -l /etc/anacrontab to ensure permissions is correct and remove the output with "/dev/null"
	printf "\033[33;32m PASS \n"
else
	printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Checking if /etc/crontab file has the correct permissions \n"
if ls -ld /etc/crontab | grep -e -rw------- >/dev/null; then  # Grep the permissions from ls -ld /etc/crontab to ensure permissions is correct and remove the output with "/dev/null"
	printf "\033[33;32m PASS \n"
else
	printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Checking if /etc/cron.hourly file has the correct permissions \n"
if ls -ld /etc/cron.hourly | grep drwx------ >/dev/null; then # Grep the permissions from ls -l /etc/cron.hourly to ensure permissions is correct and remove the output with "/dev/null"
	printf "\033[33;32m PASS \n"
else
	printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Checking if /etc/cron.daily file has the correct permissions \n"
if ls -ld /etc/cron.daily | grep drwx------ >/dev/null; then # Grep the permissions from ls -ld /etc/cron.daily to ensure permissions is correct and remove the output with "/dev/null"
	printf "\033[33;32m PASS \n"
else
	printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Checking if /etc/cron.weekly file has the correct permissions \n"
if ls -ld /etc/cron.weekly | grep drwx------ >/dev/null; then  # Grep the permissions from ls -ld /etc/cron.weekly to ensure permissions is correct and remove the output with "/dev/null"
	printf "\033[33;32m PASS \n"
else
	printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Checking if /etc/cron.monthly file has the correct permissions \n"
if ls -ld /etc/cron.monthly | grep drwx------ >/dev/null; then # Grep the permissions from ls -ld /etc/cron.monthly to ensure permissions is correct and remove the output with "/dev/null"
	printf "\033[33;32m PASS \n"
else
	printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Checking if /etc/cron.d directory has the correct permissions \n"
if ls -ld /etc/cron.d | grep drwx------ >/dev/null; then # Grep the permissions from ls -ld /etc/cron.d to ensure permissions is correct and remove the output with "/dev/null"
	printf "\033[33;32m PASS \n"
else
	printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Checking if at jobs are restricted \n"
if stat -L -c "%a %u %g" /etc/at.allow | egrep ".00 0 0" >/dev/null; then #Issing this command with an output shows that the system is configured correctly
	printf "\033[33;32m PASS \n"
else
	printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Checking if cron is restricted to Authorized Users \n"
if ls -l /etc/cron.allow | grep -e -rw------- >/dev/null; then # Grep the permissions from ls -l /etc/cron.allow to ensure permissions is correct and remove the output with "/dev/null"
	printf "\033[33;32m PASS \n"
else
	printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Checking if at is restricted to Authorized Users \n"
if ls -l /etc/at.allow | grep -e -rw------- >/dev/null; then # Grep the permissions from ls -l /etc/at.allow to ensure permissions is correct and remove the output with "/dev/null"
	printf "\033[33;32m PASS \n"
else
	printf "\033[33;31m FAIL \n"
fi

#10

printf "\e[0m Checking if the SSH protocol is correct:  \n"
if grep "^Protocol 2" /etc/ssh/sshd_config > /dev/null; then # Grep "Protocol 2" to ensure settings is correct and remove the output with "/dev/null"
	printf "\033[33;32m PASS \n"
else
	printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Checking if the SSH loglevel is correct:  \n"
if grep "^LogLevel INFO" /etc/ssh/sshd_config > /dev/null; then # Grep "LogLevel INFO" to ensure settings is correct and remove the output with "/dev/null"
        printf "\033[33;32m PASS \n"
else
        printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Checking the SSH permissions:  \n"
if /bin/ls -l  /etc/ssh/sshd_config | grep -e "-rw-------. 1 root root" > /dev/null ; then # Grep the permissions from ls -l /etc/ssh/sshd_config to ensure permissions is correct and remove the output with "/dev/null"
        printf "\033[33;32m PASS \n"
else
        printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Checking if X11Forwarding is disabled:  \n"
if grep "^X11Forwarding no" /etc/ssh/sshd_config > /dev/null; then # Grep "X11Forwarding no" to ensure settings is correct and remove the output with "/dev/null"
        printf "\033[33;32m PASS \n"
else
        printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Checking if the MaxAuthTries is correct:  \n"
if grep "^MaxAuthTries 4" /etc/ssh/sshd_config > /dev/null; then # Grep "MaxAuthTries 4" to ensure settings is correct and remove the output with "/dev/null"
        printf "\033[33;32m PASS \n"
else
        printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Checking if IgnoreRhosts is enabled:  \n"
if grep "^IgnoreRhosts yes" /etc/ssh/sshd_config > /dev/null; then # Grep "IgnoreRhosts yes" to ensure settings is correct and remove the output with "/dev/null"
        printf "\033[33;32m PASS \n"
else
        printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Checking if HostbasedAuthentication is disabled:  \n"
if grep "^HostbasedAuthentication no" /etc/ssh/sshd_config > /dev/null; then # Grep "HostbasedAuthentication no" to ensure settings is correct and remove the output with "/dev/null"
        printf "\033[33;32m PASS \n" 
else
        printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Checking if PermitRootLogin is disabled:  \n"
if grep "^PermitRootLogin no" /etc/ssh/sshd_config > /dev/null; then # Grep "PermitRootLogin no" to ensure settings is correct and remove the output with "/dev/null"
        printf "\033[33;32m PASS \n"
else
        printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Checking if PermitEmptyPasswords is disabled:  \n"
if grep "^PermitEmptyPasswords no" /etc/ssh/sshd_config > /dev/null; then # Grep "PermitEmptyPasswords no" to ensure settings is correct and remove the output with "/dev/null"
        printf "\033[33;32m PASS \n"
else
        printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Checking if the Approved Cipers is correct:  \n"
if grep "^Ciphers aes128-ctr,aes192-ctr,aes256-ctr" /etc/ssh/sshd_config > /dev/null; then # Grep "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" to ensure settings is correct and remove the output with "/dev/null"
        printf "\033[33;32m PASS \n"
else
        printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Checking if ClientAliveInterval is correct:  \n"
if grep "^ClientAliveInterval 300" /etc/ssh/sshd_config > /dev/null; then # Grep "ClientAliveInterval 300" to ensure settings is correct and remove the output with "/dev/null"
        printf "\033[33;32m PASS \n"
else
        printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Checking if ClientAliveCountMax is correct:  \n"
if grep "^ClientAliveCountMax 0" /etc/ssh/sshd_config > /dev/null; then # Grep "ClientAliveCountMax 0" to ensure settings is correct and remove the output with "/dev/null"
        printf "\033[33;32m PASS \n"
else
        printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Checking the Allowed Users:  \n \033[33;32m"
if grep "^AllowUsers[[:space:]]" /etc/ssh/sshd_config > /dev/null; then # Grep "AllowUsers[[:space:]]" to check if there are any users and remove the output with "/dev/null"
	grep "^AllowUsers" /etc/ssh/sshd_config | sed -n -e 's/^.*AllowUsers //p'
else
        printf "\033[33;31m Empty \n"
fi

printf "\e[0m Checking the Allowed Groups:  \n \033[33;32m"
if grep "^AllowGroups[[:space:]]" /etc/ssh/sshd_config > /dev/null; then # Grep "AllowGroups[[:space:]]" to check if there are any groups and remove the output with "/dev/null"
	grep "^AllowGroups" /etc/ssh/sshd_config | sed -n -e 's/^.*AllowGroups //p'
else
        printf "\033[33;31m Empty \n"
fi

printf "\e[0m Checking the Denied Users:  \n \033[33;32m"
if grep "^DenyUsers[[:space:]]" /etc/ssh/sshd_config > /dev/null; then # Grep "DenyUsers[[:space:]]" to check if there are any users and remove the output with "/dev/null"
	grep "^DenyUsers" /etc/ssh/sshd_config | sed -n -e 's/^.*DenyUsers //p'
else
        printf "\033[33;31m Empty \n"
fi

printf "\e[0m Checking the Denied Groups:  \n \033[33;32m"
if grep "^DenyGroups[[:space:]]" /etc/ssh/sshd_config > /dev/null; then # Grep "DenyGroups[[:space:]]" to check if there are any groups and remove the output with "/dev/null"
	grep "^DenyGroups" /etc/ssh/sshd_config | sed -n -e 's/^.*DenyGroups //p'
else
        printf "\033[33;31m Empty \n"
fi

printf "\e[0m Checking if SSH Banner is correct:  \n"
if grep "^Banner /etc/issue.net" /etc/ssh/sshd_config > /dev/null ; then # Grep "Banner /etc/issue.net" to ensure settings is correct and remove the output with "/dev/null"
        printf "\033[33;32m PASS \n"
else
        printf "\033[33;31m FAIL \n"
fi

#11

printf "\e[0m Checking if password-hashing algorithm is set to SHA-512 \n "
if authconfig --test | grep hashing | grep sha512 >/dev/null; then
	printf "\033[33;32m PASS \n"
else
	printf "\033[33;31m FAIL \n"
fi



printf "\e[0m Determine the current settings in /etc/pam.d/systemauth \n "
if grep pam_pwquality.so /etc/pam.d/system-auth >/dev/null; then # Grep "pam_pwquality.so" to ensure settings is correct and remove the output with "/dev/null"
	printf "\033[33;32m PASS \n"
else
	printf "\033[33;31m FAIL \n"
fi



printf "\e[0m Settings in /etc/security/pwquality.conf \n "

printf "\e[0m Checking minlen \n"
if cat /etc/security/pwquality.conf | grep "^minlen = 14" > /dev/null; then # Grep "minlen = 14" from /etc/security/pwquality.conf and remove the output with "/dev/null"
	printf "\033[33;32m PASS \n"
else
	printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Checking dcredit \n"
if cat /etc/security/pwquality.conf | grep "^dcredit = -1" >/dev/null; then # Grep "dcredit = -1" from /etc/security/pwquality.conf and remove the output with "/dev/null"
	printf "\033[33;32m PASS \n"
else
	printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Checking ucredit \n"
if cat /etc/security/pwquality.conf | grep "^ucredit = -1" >/dev/null; then # Grep "ucredit = -1" from /etc/security/pwquality.conf and remove the output with "/dev/null"
	printf "\033[33;32m PASS \n"
else
	printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Checking ocredit \n"
if cat /etc/security/pwquality.conf | grep "ocredit = -1" >/dev/null; then # Grep "ocredit = -1" from /etc/security/pwquality.conf and remove the output with "/dev/null"
	printf "\033[33;32m PASS \n"
else
	printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Checking lcredit \n"
if cat /etc/security/pwquality.conf | grep "lcredit = -1" >/dev/null; then # Grep "lcredit = -1" from /etc/security/pwquality.conf and remove the output with "/dev/null"
	printf "\033[33;32m PASS \n"
else
	printf "\033[33;31m FAIL \n"
fi


printf "\e[0m Determine the current settings in userID lockout \n "
printf "\e[0m Password-auth \n"
if grep pam_faillock /etc/pam.d/password-auth > /dev/null; then # Grep "pam_faillock" from /etc/pam.d/password-auth and remove the output with "/dev/null"
	printf "\033[33;32m PASS \n"
else
	printf "\033[33;31m FAIL \n"
fi

printf "\e[0m System-auth \n"
if grep pam_faillock /etc/pam.d/system-auth > /dev/null; then # Grep "pam_faillock" from /etc/pam.d/system-auth and remove the output with "/dev/null"
	printf "\033[33;32m PASS \n"
else
	printf "\033[33;31m FAIL \n"
fi

printf "\e[0m Determine the current settings for reusing of older passwords \n "
if grep "remember=5" /etc/pam.d/system-auth >/dev/null; then # Grep "remember=5" from /etc/pam.d/system-auth and remove the output with "/dev/null"
	printf "\033[33;32m PASS \n"
else
	printf "\033[33;31m FAIL \n"
fi


printf "\e[0m Determine if restriction of login to system console is configured correctly \n "
if ls -ld /etc/securetty| cut -d " " -f 5 | grep 0 > /dev/null; then
	printf "\033[33;32m PASS \n"
else
	printf "\033[33;31m FAIL \n"
fi
	


printf "\e[0m \n Restrict Access to the su command \n "

if cat /etc/pam.d/su | grep "^auth		required	pam_wheel.so use_uid" > /dev/null; then # Grep "auth		required	pam_wheel.so use_uid" from /etc/pam.d/su and remove the output with "/dev/null"
	printf "\033[33;32m PASS \n"
else
	printf "\033[33;31m FAIL \n"
fi
printf "\e[0m Users that are allowed to issue su command: \n "
echo -en "\033[33;31m" > /dev/null
cat /etc/group | grep wheel | cut -d : -f 4 #Grep "wheel" from /etc/group and cut out the 4th field 

echo -en "\e[0m" #reverts the text color to black
