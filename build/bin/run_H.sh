#!/bin/bash

for k in {0..4}
do
    for b in {3..12}
    do
    	./share-OT-H r=1 pS=11000 pC=11002 Pdim=$k Psize=0 Pbran=$b & ./share-OT-H r=2 pS=11001 pC=11000 Pdim=$k Psize=0 Pbran=$b &./share-OT-H r=3 pS=11002 pC=11001 Pdim=$k Psize=0 Pbran=$b
        sleep 2
    done
done

