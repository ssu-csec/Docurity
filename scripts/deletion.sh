Binary=$1
Tmpfile=$2
Output=$3
MAX_SIZE=$4
Constant=${5:-0}
Threshold=1200
Operation1="Insert"
Operation2="Delete"
Inversed_index=$(($MAX_SIZE-$Threshold))
echo "$0 ${Binary} ${Tmpfile} ${MAX_SIZE}" 

rm $Tmpfile

echo "${Operation1}" >> $Tmpfile
echo "0" >> $Tmpfile
./string_printer $((${MAX_SIZE})) >> $Tmpfile
for ((i=1; i<$MAX_SIZE+1; i++))
do
	echo "${Binary} ${i}" 
	echo "${Operation2}" >> $Tmpfile
	echo "$Inversed_index" >> $Tmpfile
	echo "$MAX_SIZE" >> $Tmpfile
	Threshold=$(($Threshold * 2))
	Inversed_index=$(($Inversed_index-$Threshold))

	if [ $Inversed_index -lt 0 ]; then break; fi
done

./$Binary $Tmpfile> $Output
