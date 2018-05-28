# FreeIPA-Scripts
Collection of Scripts to Use with FreeIPA and FreeIPA clients

In the HPUX & Solaris Folder there is an sshd_config ldap script to pull ssh keys from FreeIPA servers. 
Place the script on the server owned by root with execute permissions (do not place write privileges), 
place the directive sshauthorizedkeys "script location/script" in the sshd_config.  
You can also run the script with a username and see if it will return the key(s) from FreeIPA.
