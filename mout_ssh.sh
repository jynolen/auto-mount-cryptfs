#!/bin/bash

if [[ -d /block/cipher/$USER ]]; then
    ssh-add -l >/dev/null 2>/dev/null
    if [[ $? -eq 0 ]]; then
      mkdir -p $HOME/private
      screen -d -m ssh_mount --volume /block/cipher/$USER unlock --target $HOME/private
    fi
fi

 ➜ cat /etc/pam.d/common-session |tail -n 2
# end of pam-auth-update config
session optional pam_exec.so /usr/local/bin/ssh_mount --volume "" unmount
  ➜ cat /usr/local/bin/ssh_mount
#!/bin/sh
/opt/ssh_mount/bin/python /opt/ssh_mount/ssh_mount.py $@
