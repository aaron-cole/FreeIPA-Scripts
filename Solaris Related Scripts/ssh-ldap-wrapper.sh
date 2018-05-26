#!/usr/bin/sh
##########################################################
# /etc/ssh/ssh-ldap-wrapper.sh
# 
# This script was created to connected to RedHat IDM server
# also known as a freeipa server, for ssh public key logins
# to work.  This script will search the idm server for the
# user name ($2) by sun-ssh (Solaris secure shell) 
# and return the ssh rsa-key for the user, compare current
# keys and add if necessary.  Also added lines to create
# home directory, since no pam_mkhomedir exists in solaris.
# 
# Modification of this file is very bad and could stop ssh logins 
# from happening, unless using in a different environment.
# Otherwise modify the variables as needed.
#
# This is valid for Solaris 11.3 and no other OS.
# Do not use on a different OS.
#
# Change all places with example.com or dc=example,dc=com to 
# Reflect you structure
#
# This file was created:
# By Aaron Cole
#                                                                                                                    
# Date:
# 11/15/2016
#
# Change Log:
# Version 1.0 - 11/15/2016: 
# -Initial Creation
#
# Version 1.1 - 12/02/2016: 
# -Discovered all Solaris 11 servers may not have nslookoup on them.  
#  Added if statement to pull server entries from dns if applicable,
#  and if not then pull from /etc/ldap.conf (should be there for sudoers).
# -Changed main for loop from nslookup command to $servers variable. 
# 
# Version 1.2 - 12/05/2016: 
# -Updated to disregard local users
#
# Version 1.3 - 8/7/2017: 
# -Updated to process HBAC rules for logins.
#
# Version 1.4 - 3/28/2018
# -Added Trailing colon for local users
# -Refined HBAC rule lookup, to keep ldapsearches to a minimum.
#  Should speed up login on first found allow rule. 
# -Added multiple variables to support HBAC rule lookup
# -Commented out nslookup for $server dns seems to be taking a long time
# -Cleanup commented out items, and redone Changelog format.
##########################################################
#Exit if there is not an argument
#argument = username

if [ -z $2 ]; then
 exit 2
fi

#Version 1.2
#Version 1.4 -Trailing colon is important
if grep ^$2: /etc/passwd >>/dev/null; then
 exit 0
fi

#Variables
#Change These variables#
#Proxy User information
userdn="uid=proxyagent,ou=profile,dc=example,dc=com"
userpass="P@ssW0rd!!P@ssW0rd"

#DN's for freeipa structure - only change dc part
basedn="dc=example,dc=com"
hbacdn="cn=hbac,dc=example,dc=com"
compdn="cn=computers,cn=accounts,dc=example,dc=com"
hostgroupdn="cn=hostgroups,cn=accounts,dc=example,dc=com"
usrgrpdn="cn=groups,cn=accounts,dc=example,dc=com"


uid="$2"
gid="$(getent passwd $uid | cut -f 4 -d ":")"
umask 0077
my_pid=$$
rule_file="/tmp/rule_file.$my_pid"
main_ldap_filter_allow="(&(objectClass=ipahbacrule)(ipaEnabledFlag=TRUE)(accessRuleType=allow)(|(serviceCategory=all)(memberService=sshd)))"
main_ldap_filter_deny="(&(objectClass=ipahbacrule)(ipaEnabledFlag=TRUE)(accessRuleType=deny)(|(serviceCategory=all)(memberService=sshd)))"
userallow=0

#Define IDM server to use
#Use DNS otherwise use ldap.conf
#Version 1.4 - removing nslookup just use randnum from ldap.conf
#if [ -f /usr/sbin/nslookup ]; then
# server="$(/usr/sbin/nslookup -type=SRV _ldap._tcp.example.com | grep "^_ldap" | awk '{ print $7}' | sed s/.$// | head -1)"
#else
 randnum="$(shuf -i 1-2 -n 1)"
 server="$(grep ^URI /etc/ldap.conf | sed 's/ldap\:\/\///g' | sed 's/^URI //' | cut -f $randnum -d " ")" 
#fi

##########################################################
#Do not change below this
##########################################################

check_rule()
{

 #Dump rule to file so we can check it
 /usr/bin/ldapsearch -b $hbacdn -B -x -h $server -D $userdn -w $userpass cn=$rule > $rule_file
    
 #Check if rule applies to host - hostname hostgroup or all
 #This is all
 hostpass=0
 if [ "$(grep "^hostCategory" $rule_file | cut -f 2 -d "=")" = "all" ] ; then
  hostpass=1
  #This is member host
 else
   temphostname=$(hostname)
     lowerhostname="$(echo $temphostname | tr '[A-Z]' '[a-z]')"
     underlowhostname="$(echo $lowerhostname | tr '_' '-')"
     for memberhostentry in $(grep "memberHost" $rule_file); do
       if [ $hostpass = "0" ]; then
         case $memberhostentry in

                #hostname match
                memberHost=fqdn=$underlowhostname*) 
                   hostpass=1
                   ;;
                
                #non fqdn entries
                memberHost=cn=*) 
                   testgroup="$(echo $memberhostentry | cut -f 1 -d "," | cut -c 12- )"
                   if /usr/bin/ldapsearch -b $hostgroupdn -x -h $server -D $userdn -w $userpass $testgroup | grep "fqdn=$lowerhostname" > /dev/null; then
                      hostpass=1
                   fi
                   ;;

         esac
       fi
     done
 fi #End of member host rule
        
 #check member users
 usercheck=0
 if [ $hostpass -ge 1 ]; then
     if [ "$(grep "userCategory" $rule_file | cut -f 2 -d "=")" = "all" ] ; then
      #All users a memebers is userCategory is all
      usercheck=1
     else
       # Loop over the memberUsers.  Could be a user or a group
       for memberuserentry in $(grep "memberUser" $rule_file ); do
         if [ $usercheck -eq 0 ]; then
           case $memberuserentry in
             #hostname user - Added comma below to ensure right username is processed
              memberUser=uid=$uid,*)
                 usercheck=1
                 ;;
                
              #Check if user is part of a group on the rule
              memberUser=cn=*)
                 testgroup="$(echo $memberuserentry | cut -f 1 -d "," | cut -c 15- )"
                 # If we can, use ldaplist, it should use client cache
                 if /usr/bin/ldaplist -l group $testgroup | grep "memberUid: $uid" > /dev/null; then
                   usercheck=1
                 fi
                 ;;

           esac
         fi
       done
     fi 
 fi  

}

#Exit on bad usernames
if ! expr "$uid" : '[a-zA-Z0-9._-]*$' 1>/dev/null; then
        exit 2
fi

#only get enabled rules to cut down on later searchs
#For each Rule
for rule in $(/usr/bin/ldapsearch -b $hbacdn -x -h $server -D $userdn -w $userpass "$main_ldap_filter_allow" cn | grep "^cn:"  | cut -d " " -f 2); do 

  #Process if user hasn't been allowed already 
  if  [ "$userallow" -eq 0 ]; then

     check_rule

     if [ "$usercheck" -eq 1 ]; then
        userallow=1
     fi

   fi # End of processing if user is already allowed and rule is allow
done

#done with allow rules.  Since the default is deny if we didn't find any
# that matched, then go no further and dump the user out.
if [ "$userallow" -eq 0 ] ; then
  rm -rf $rule_file > /dev/null 2>&1
  exit 2
fi

# Now check to see if we have any deny rules and if at least one matches.
#only get enabled rules to cut down on later searchs

usercheck=0 
#For each Rule
for rule in $(/usr/bin/ldapsearch -b $hbacdn -x -h $server -D $userdn -w $userpass "$main_ldap_filter_deny" cn | grep "^cn:"  | cut -d " " -f 2); do

     check_rule

     if [ "$usercheck" -eq 1 ]; then
        # This deny rule matched, just cleanup and dump out with error
        rm -rf $rule_file > /dev/null 2>&1
        exit 2
     fi

done

# User is allowed to login, pull the pubkey.  Echo to stdout will pass 
# it back to our caller, the sshd process.
# However SunSSH sucks so we have to do more work

if [ "$userallow" -ge 1 ]; then
 keys="$(/usr/bin/ldapsearch -b $basedn -LLL -T -x -h $server -D $userdn -w $userpass "(&(uid=$uid)(ipaSshPubKey=*))" 'ipaSshPubKey' | sed -n 's/^ipaSshPubKey:\s*\(.*\)$/\1/p' | cut -c 2- )"
# echo "$keys"
#SunSSH sucks
#Checking if key exists in authorized_keys2
#If it is there, we are good to go and can exit
 if grep "$keys" ~$uid/.ssh/authorized_keys2 >>/dev/null 2>>/dev/null; then
  exit 0

#If home dir doesn't exist got to create it
#then drop in key and correctly chown it
 elif [ ! -d ~$uid ]; then
  mkdir -p ~$uid/.ssh
  cp /etc/skel/* ~$uid/
  echo "$keys" > ~$uid/.ssh/authorized_keys2
  chown -R $uid:$gid ~$uid
  exit 0

#If the .ssh dir doesn't exist got to create it
#then drop in key and correctly chown it 
 elif [ ! -d ~$uid/.ssh ]; then
  mkdir ~$uid/.ssh
  echo "$keys" > ~$uid/.ssh/authorized_keys2
  chown -R $uid:$gid ~$uid
  exit 0

#If authorized_keys2 doesn't exist 
#then drop in key and correctly chown it  
 elif [ ! -f ~$uid/.ssh/authorized_keys2 ]; then 
  echo "$keys" > ~$uid/.ssh/authorized_keys2
  chown -R $uid:$gid ~$uid
  exit 0 

#Otherwise drop the key in the file
 else
  echo "$keys" > ~$uid/.ssh/authorized_keys2
  chown -R $uid:$gid ~$uid  
  exit 0
 fi
fi

#Cleanup
rm -rf $rule_file > /dev/null 2>&1