#!/bin/bash


echo "Installing prerequisites..."
sudo apt-get update
sudo apt-get install -y build-essential python3-dev libgmp-dev libssl-dev git wget


echo "Installing PBC..."
git clone https://github.com/blynn/pbc.git
cd pbc
./configure
make
sudo make install
sudo ldconfig
cd ..


echo "Installing charm-crypto..."
git clone https://github.com/JHUISI/charm.git
cd charm
./configure.sh
python3 setup.py build
python3 setup.py install --user


echo "Setting environment variables..."
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
export PYTHONPATH=$HOME/.local/lib/python3.8/site-packages:$PYTHONPATH


echo "Testing charm-crypto installation..."
python3 -c "from charm.toolbox.pairinggroup import PairingGroup; print(PairingGroup('SS512'))"

echo "Installation completed!"
