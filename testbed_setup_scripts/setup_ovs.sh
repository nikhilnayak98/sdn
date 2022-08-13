sudo nano /etc/default/grub

sudo update-grub

sudo reboot

sudo apt-get install openvswitch-switch

sudo ovs-vsctl show

sudo ovs-vsctl add-br br0

sudo ovs-vsctl add-port br0 eth1

sudo ovs-vsctl add-port br0 eth2

sudo ovs-vsctl add-port br0 eth3

sudo nano /etc/network/interfaces

sudo reboot

sudo ovs-vsctl set-controller br0 tcp:192.168.1.10:6633

sudo ovs-vsctl add-port br0 eth0

sudo ovs-vsctl

sudo ovs-vsctl show