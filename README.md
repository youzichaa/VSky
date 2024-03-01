# VSky
The source code is located in ./test/test_ring_share.cpp

run the code:

`cd ./build/`

`cmake -DCMAKE_INSTALL_PREFIX=./install .. -DBUILD_TESTS=ON -DBUILD_NETWORKS=ON`

`cmake --build . --target install --parallel`

the "share-OT.o" file is generated. 

Please move to the "run" file:

`cd /build/bin/`

To test the files, we prepared the relevant executables, where "share-OT-S" stands for semi-honest model, "share-OT-M" for malicious model, and "share-OT-100000-S/M" for large dataset. 
Moreover, we construct shell files where: 

1. "k" denotes the dimension (0 to 4, representing 3 to 7 dimensions),
2. "i" denotes the dataset (0 to 3, representing three datasets：corr, anti, inde),
3. "j" denotes the size of the dataset (0 to 5, representing (1000, 3000, 5000, 7000, and 11000)),
4. "b" denotes the size of the branch (3 to 12).

For example, run the command.

`nohup ./run_S.sh >output.txt 2>&1 &`

, the whole console output is stored in "output.txt".

You can also be executed individually with the following command:

`./share-OT-S r=1 pS=9000 pC=9002 Pdim=0 Pname=0 Psize=0 Pbran=3 & ./share-OT-S r=2 pS=9001 pC=9000 Pdim=0 Pname=0 Psize=0 Pbran=3  &./share-OT-S r=3 pS=9002 pC=9001 Pdim=0 Pname=0 Psize=0 Pbran=3`

the test result is generated in the following file:

./test/out_1.txt, ./test/out_2.txt, ./test/out_3.txt

The Skyline Number, Query Time, Verify Time, and Communication are printed. For example:
![image](https://github.com/youzichaa/VSky/assets/41678928/8fc1c26f-f601-4cb3-88ac-74d715d2fbba)
