Binary=$1
Tmpfile=$2
Output=$3
MAX_SIZE=$4
Constant=$5
Threshold=$((12+$Constant))
Operation="Delete"
Inversed_index=$(($MAX_SIZE-$Threshold))
echo "$0 ${Binary} ${Tmpfile} ${MAX_SIZE}" 

rm $Tmpfile

./string_printer ${MAX_SIZE}) >> $Tmpfile
for ((i=1; i<$MAX_SIZE+1; i++))
do
	echo "${Binary} ${i}" 
	echo "${Operation}" >> $Tmpfile
	echo "$Inversed_index" >> $Tmpfile
	echo "$Threshold" >> $Tmpfile
	Threshold=$(($Threshold * 2))
	Inversed_index=$(($Inversed_index-$Threshold))
done

./$Binary $Tmpfile> $Output