wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
sudo python2 ./get-pip.py
sudo python2 -m pip install --upgrade setuptools
sudo python2 -m pip install jsmin
cd /opt/
sudo git clone https://github.com/mdsecactivebreach/SharpShooter.git
cd SharpShooter/
sudo python2 -m pip install -r requirements.txt
