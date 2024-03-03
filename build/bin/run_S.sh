#!/bin/bash

for k in {0..4}
do
    for i in {0..2}
    do
        for j in {0..5}
        do
            for b in {3..12}
            do
                ./share-OT-S r=1 pS=9000 pC=9002 Pdim=$k Pname=$i Psize=$j Pbran=$b & ./share-OT-S r=2 pS=9001 pC=9000 Pdim=$k Pname=$i Psize=$j Pbran=$b &./share-OT-S r=3 pS=9002 pC=9001 Pdim=$k Pname=$i Psize=$j Pbran=$b
                sleep 1
            done
        done
    done
done

