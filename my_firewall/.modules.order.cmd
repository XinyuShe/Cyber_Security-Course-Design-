cmd_/home/shexinyu/my_firewall/modules.order := {   echo /home/shexinyu/my_firewall/myfw.ko; :; } | awk '!x[$$0]++' - > /home/shexinyu/my_firewall/modules.order
