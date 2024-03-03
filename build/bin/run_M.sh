#!/bin/bash

for k in {0..4}
do
    for i in {0..2}
    do
        for j in {0..5}
        do
            for b in {3..12}
            do
                ./share-OT-M r=1 pS=10000 pC=10002 Pdim=$k Pname=$i Psize=$j Pbran=$b & ./share-OT-M r=2 pS=10001 pC=10000 Pdim=$k Pname=$i Psize=$j Pbran=$b &./share-OT-M r=3 pS=10002 pC=10001 Pdim=$k Pname=$i Psize=$j Pbran=$b
                sleep 1
            done
        done
    done
done

