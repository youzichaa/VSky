for k in {0..4}
do
    for itr in {0..4}
    do
        ./share-OT-100000-S r=1 pS=9000 pC=9002 Pdim=$k Pname=0 Psize=0 Pbran=3 Pitr=$itr & ./share-OT-100000-S r=2 pS=9001 pC=9000 Pdim=$k Pname=0 Psize=0 Pbran=3 Pitr=$itr &./share-OT-100000-S r=3 pS=9002 pC=9001 Pdim=$k Pname=0 Psize=0 Pbran=3 Pitr=$itr
        sleep 2
    done
done
