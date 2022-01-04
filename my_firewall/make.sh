sudo make clean
sudo make
sudo rmmod myfw
sudo rm -r /dev/rule
sudo insmod myfw.ko 
sudo mknod /dev/rule c 238 0
gcc -o FW test.c -g
sudo sysctl -w net.ipv4.ip_forward=1

