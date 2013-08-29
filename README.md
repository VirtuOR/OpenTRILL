OpenTRILL
=========

The IETF Standard TRILL (Transparent Interconnect of Lots of Links)

Description:
The IETF Standard TRILL (Transparent Interconnect of Lots of Links) will be implemented and developed under an Open Source Initiative. It is the major contribution of a challenging company VirtuOR (France) and the Phare team from LIP6 (France). The first stable version will be available for downloading very soon.


Notice:
The open source project Linux_TRILL_development is actually no more available. We start the actuel version with a fork based on the available version downloaded from (http://wisnet.seecs.nust.edu.pk/cgi-sys/suspendedpage.cgi) and ported to the new linux kernel 3.10.7 for the moment. The improvements of the actual version is on progress. 

How to:
Commands:
- cd linux-3.10.7/
- compile the kernel and install it with the kernel needed configuration

- apt-get install dia

- cd bridge-utils-1.5/
- ./configure
- make
- make install

- cd libmnl-addadf8/
- ./configure
- make
- make install

- cd 
- ./configure
- make
- make install

- cd trill-linux-port/linux-user-space/quagga-linux-trill/isisd/
- make
- make install
- cp trill-linux-port/linux-user-space/trilld.conf /usr/local/etc/


Start TRILL:
Steps:
- make a bridge br0
- Add interfaces to bridge br0
- run trilld 

Commands:
- brctl addbr br0
- brctl addif br0 eth0
- trilld -f /usr/local/etc/trilld.conf -i "" br0
